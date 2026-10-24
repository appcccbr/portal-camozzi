#!/usr/bin/env python3
"""Gera o Portal de Catálogos Camozzi a partir da pasta pública do Google Drive.

Uso:
  PORTAL_PASSWORD=... python3 -I build.py --catalog catalog.json --template template.html --out site

Passos:
  1. Lista a pasta do Drive (e subpastas) pela visualização pública embutida.
  2. Baixa cada PDF completo.
  3. Extrai o texto de cada página e o cabeçalho (capítulo / família / série / seção).
  4. Monta o sumário automático a partir dos cabeçalhos.
  5. Aplica a classificação de catalog.json (PDFs sem classificação entram como "auto" e
     são listados em site/_pendentes.json para revisão).
  6. Criptografa índice e PDFs com AES-256-GCM (chave PBKDF2-SHA256 da senha).
  7. Grava site/index.html, site/vault.json, site/d/*.bin e site/_manifest.json.

Só lê a pasta indicada em catalog.json -> folder_id.
"""
import argparse, base64, gzip, hashlib, html, json, os, re, shutil, subprocess, sys, time, urllib.parse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import pypdf

PBKDF2_ITER = 600_000
MAX_PART = 11 * 1024 * 1024  # em base64 vira ~14,7 MB (limite de texto publicado: 16 MB)
IGNORAR = {"PNEUMATIC ACTUATION", "ELECTRIC ACTUATION", "•"}
CURL = ["curl", "-sSL", "--max-time", "300", "--retry", "2"]


def http_get(url, dest=None):
    cmd = CURL + ([ "-o", dest] if dest else []) + ["-w", "\n__HTTP__%{http_code}", url]
    if dest:
        out = subprocess.run(cmd, capture_output=True, text=True)
        code = out.stdout.strip().split("__HTTP__")[-1]
        if code != "200":
            raise RuntimeError(f"HTTP {code} ao baixar {url}: {out.stderr.strip()}")
        return None
    out = subprocess.run(cmd, capture_output=True)
    body, _, code = out.stdout.rpartition(b"\n__HTTP__")
    if code.decode().strip() != "200":
        raise RuntimeError(f"HTTP {code.decode()} em {url}")
    return body.decode("utf-8", "replace")


def list_folder(folder_id, path=(), depth=0):
    """Lista PDFs da pasta pública (recursivo, até 6 níveis)."""
    page = http_get(f"https://drive.google.com/embeddedfolderview?id={folder_id}#list")
    items = []
    for m in re.finditer(r'<div class="flip-entry" id="entry-([A-Za-z0-9_-]+)".*?<div class="flip-entry-title">(.*?)</div>', page, re.S):
        fid, title = m.group(1), html.unescape(m.group(2)).strip()
        block = m.group(0)
        if "/drive/folders/" in block:
            if depth < 6:
                items += list_folder(fid, path + (title,), depth + 1)
        elif title.lower().endswith(".pdf"):
            items.append({"id": fid, "arquivo": title, "pasta": list(path)})
    return items


def norm_section(raw):
    s = raw.strip().upper()
    s = re.sub(r"\s+", " ", s)
    return s


def parse_header(lines):
    """Cabeçalho padrão dos catálogos Camozzi:
    0: CHAPTER / AAAA/MM   1: FAMÍLIA   2: SERIES X - SEÇÃO   3: assunto da página"""
    head = {"capitulo": "", "edicao": "", "familia": "", "serie": "", "secao": "GERAL", "assunto": ""}
    ls = [l.strip() for l in lines if l.strip() and not re.fullmatch(r"\d{1,3}", l.strip()) and l.strip() != "•"]
    if not ls:
        return head
    m = re.match(r"(.+?)\s*/\s*(\d{4}/\d{2})\s*$", ls[0])
    if not m:
        head["assunto"] = ls[0][:120]
        return head
    head["capitulo"], head["edicao"] = m.group(1).strip(), m.group(2)
    rest = ls[1:]
    if rest:
        head["familia"] = rest[0]
    if len(rest) > 1:
        s = rest[1]
        if " - " in s:
            serie, sec = s.split(" - ", 1)
            head["serie"], head["secao"] = serie.strip(), norm_section(sec)
        else:
            head["serie"] = s.strip()
    if len(rest) > 2:
        cand = rest[2]
        # descarta linhas que são listas de características (página de capa)
        head["assunto"] = cand[:140]
    return head


def extract(pdf_path):
    reader = pypdf.PdfReader(pdf_path)
    n = len(reader.pages)
    raw = subprocess.run(["pdftotext", "-enc", "UTF-8", pdf_path, "-"], capture_output=True, text=True).stdout
    pages = raw.split("\f")[:n]
    while len(pages) < n:
        pages.append("")
    lay = subprocess.run(["pdftotext", "-enc", "UTF-8", "-layout", pdf_path, "-"], capture_output=True, text=True).stdout.split("\f")
    texts, heads = [], []
    for i, t in enumerate(pages):
        hl = []
        for l in (lay[i] if i < len(lay) else t).splitlines()[:20]:
            seg = re.split(r"\s{3,}", l.strip())[0].strip()
            if seg and seg.upper() not in IGNORAR:
                hl.append(seg)
        heads.append(parse_header(hl[:12]))
        clean = re.sub(r"[ \t]+", " ", t)
        clean = re.sub(r"\n\s*\n+", "\n", clean).strip()
        # remove o rodapé legal repetido em todas as páginas
        clean = re.sub(r"Products designed for industrial applications\..*?shop\.camozzi\.com", "", clean, flags=re.S)
        texts.append(clean)
    return n, texts, heads


def build_toc(heads, secoes):
    toc = []
    for i, h in enumerate(heads, start=1):
        sec = h["secao"] if i > 1 else "GERAL"
        label = secoes.get(sec, sec.capitalize())
        if not toc or toc[-1]["k"] != sec:
            toc.append({"k": sec, "t": label, "p": i, "items": []})
        assunto = h["assunto"] if i > 1 else "Apresentação e dados gerais"
        if assunto and (not toc[-1]["items"] or toc[-1]["items"][-1]["t"] != assunto):
            toc[-1]["items"].append({"t": assunto, "p": i})
    for s in toc:
        s.pop("k")
    return toc


def cover_photo(pdf_path, workdir):
    """Maior foto da primeira página (a foto de produto da capa), reduzida para JPEG."""
    from PIL import Image
    tmp = os.path.join(workdir, "_img")
    shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)
    subprocess.run(["pdfimages", "-f", "1", "-l", "1", "-png", pdf_path, os.path.join(tmp, "i")], capture_output=True)
    best, area = None, 0
    for f in os.listdir(tmp):
        try:
            im = Image.open(os.path.join(tmp, f))
        except Exception:
            continue
        if min(im.size) >= 300 and im.size[0] * im.size[1] > area:
            best, area = im, im.size[0] * im.size[1]
    if best is None:
        return None
    im = best.convert("RGB")
    im.thumbnail((720, 720))
    import io
    buf = io.BytesIO(); im.save(buf, "JPEG", quality=84, optimize=True)
    return buf.getvalue()


def split_pdf(path, n, workdir, base):
    size = os.path.getsize(path)
    if size <= MAX_PART:
        return [(path, 1, n)]
    parts_needed = -(-size // MAX_PART) + 1
    per = -(-n // parts_needed)
    out = []
    while True:
        out = []
        for a in range(1, n + 1, per):
            b = min(n, a + per - 1)
            p = os.path.join(workdir, f"{base}_{a}-{b}.pdf")
            subprocess.run(["qpdf", "--empty", "--pages", path, f"{a}-{b}", "--", p], check=True)
            out.append((p, a, b))
        if all(os.path.getsize(p) <= MAX_PART for p, _, _ in out) or per == 1:
            return out
        per = max(1, per // 2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--catalog", default="catalog.json")
    ap.add_argument("--template", default="template.html")
    ap.add_argument("--out", default="site")
    ap.add_argument("--cache", default="cache")
    ap.add_argument("--previous-vault", help="vault.json publicado hoje (reaproveita a chave e evita reenviar arquivos que não mudaram)")
    ap.add_argument("--published", nargs="*", default=[], help="arquivos publicados hoje (lista do artifact)")
    ap.add_argument("--restore-config", nargs=2, metavar=("VAULT_JSON", "CONFIG_FILE"),
                    help="descriptografa a configuração publicada e grava em --catalog, depois sai")
    ap.add_argument("--apply-org", metavar="JSON", help="aplica a organização enviada pelo botão Organizar e sai")
    ap.add_argument("--format", choices=["bin", "b64"], default="bin", help="bin: arquivos .pdf binários (menor); b64: texto .txt")
    ap.add_argument("--pages-dir", help="pasta do repositório do portal (Cloudflare Pages): recebe o site completo")
    ap.add_argument("--portal-url", default="", help="endereço público do portal (aparece no painel de administração)")
    a = ap.parse_args()
    password = os.environ.get("PORTAL_PASSWORD")
    if not password:
        sys.exit("Defina PORTAL_PASSWORD")

    def key_for(salt, it):
        return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=it).derive(password.encode())

    def read_blob(path, fmt):
        raw = open(path, "rb").read()
        return base64.b64decode(raw) if fmt == "b64" else raw

    if a.restore_config:
        v = json.load(open(a.restore_config[0]))
        blob = read_blob(a.restore_config[1], v.get("fmt", "b64"))
        data = AESGCM(key_for(base64.b64decode(v["salt"]), v["iter"])).decrypt(blob[:12], blob[12:], None)
        json.dump(json.loads(data), open(a.catalog, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        print("Configuração restaurada em", a.catalog)
        return

    if a.apply_org:
        cat = json.load(open(a.catalog, encoding="utf-8"))
        org = json.load(open(a.apply_org, encoding="utf-8"))
        def clean(node, lvl=0):
            out = {"id": re.sub(r"[^\w-]", "", str(node.get("id") or ""))[:40] or hashlib.sha1(json.dumps(node, sort_keys=True).encode()).hexdigest()[:8],
                   "titulo": str(node.get("titulo", "")).strip()[:80] or "Sem título",
                   "descricao": str(node.get("descricao", "")).strip()[:200],
                   "docs": [d for d in node.get("docs", []) if d in cat["docs"]],
                   "filhos": [clean(c, lvl + 1) for c in node.get("filhos", [])][:50] if lvl < 5 else []}
            if node.get("icone") in ("cilindro", "valvula"):
                out["icone"] = node["icone"]
            return out
        if "mapa" in org:
            cat["mapa"] = [clean(n) for n in org["mapa"]][:30]
        for did, ch in (org.get("docs") or {}).items():
            if did in cat["docs"]:
                for k in ("nome", "titulo"):
                    if isinstance(ch.get(k), str) and ch[k].strip():
                        cat["docs"][did][k] = ch[k].strip()[:120]
                if isinstance(ch.get("inch"), bool):
                    cat["docs"][did]["inch"] = ch["inch"]
        json.dump(cat, open(a.catalog, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        print("Organização aplicada em", a.catalog)
        return

    cat = json.load(open(a.catalog, encoding="utf-8"))
    secoes = cat.get("secoes", {})
    os.makedirs(a.cache, exist_ok=True)
    if os.path.isdir(a.out):
        shutil.rmtree(a.out)
    os.makedirs(os.path.join(a.out, "d"))

    files = list_folder(cat["folder_id"])
    print(f"{len(files)} PDF(s) na pasta")

    # mesma chave da versão publicada => arquivos que não mudaram mantêm o nome e não são reenviados
    salt, it = os.urandom(16), PBKDF2_ITER
    if a.previous_vault and os.path.exists(a.previous_vault):
        pv = json.load(open(a.previous_vault))
        try:
            k0 = key_for(base64.b64decode(pv["salt"]), pv["iter"])
            ck = base64.b64decode(pv["check"]); AESGCM(k0).decrypt(ck[:12], ck[12:], None)
            if pv.get("fmt", "b64") == a.format:
                salt, it = base64.b64decode(pv["salt"]), pv["iter"]
        except Exception:
            print("  ! vault anterior não abre com esta senha; gerando chave nova")
    aes = AESGCM(key_for(salt, it))
    ext = ".pdf" if a.format == "bin" else ".txt"

    def seal(data: bytes) -> bytes:
        iv = os.urandom(12)
        return iv + aes.encrypt(iv, data, None)

    def write_blob(data: bytes) -> str:
        name = hashlib.sha256(salt + data).hexdigest()[:20] + ext
        sealed = seal(data)
        with open(os.path.join(a.out, "d", name), "wb") as f:
            f.write(sealed if a.format == "bin" else base64.b64encode(sealed))
        return "d/" + name

    docs, pendentes = [], []
    for f in files:
        local = os.path.join(a.cache, f["id"] + ".pdf")
        if not os.path.exists(local):
            http_get(f"https://drive.usercontent.google.com/download?id={f['id']}&export=download&confirm=t", local)
        with open(local, "rb") as fh:
            if fh.read(5) != b"%PDF-":
                print(f"  ! {f['arquivo']}: não é um PDF válido, ignorado")
                continue
        n, texts, heads = extract(local)
        meta = cat["docs"].get(f["id"])
        auto = meta is None
        if auto:
            h = next((x for x in heads if x["capitulo"]), heads[0])
            series = [s.strip() for s in re.split(r",| AND ", re.sub(r"SERIES?|- INCH", "", h["serie"])) if s.strip()]
            inch = "INCH" in f["arquivo"].upper() or "- INCH" in h["serie"].upper()
            meta = {
                "arquivo": f["arquivo"],
                "nome": (" ".join(series[:1]) + " " + h["familia"].title()).strip() or f["arquivo"][:-4],
                "titulo": (h["familia"].title() + " " + h["serie"].title()).strip() or f["arquivo"][:-4],
                "titulo_en": (h["familia"] + " " + h["serie"]).strip(),
                "tipo": "Catálogo técnico" if h["capitulo"] else "Sem classificação",
                "linha": h["capitulo"].title() or (f["pasta"][0] if f["pasta"] else "Sem classificação"),
                "familia": h["familia"].title() or "Sem classificação",
                "series": series, "inch": inch,
                "edicao": h["edicao"], "idioma": "Inglês", "resumo": "",
            }
            pendentes.append({"id": f["id"], "arquivo": f["arquivo"], "pasta": f["pasta"], "sugestao": meta,
                              "primeira_pagina": texts[0][:1500]})
        foto = None  # fotos de capa não são mais usadas na navegação
        parts = []
        for p, s0, e in split_pdf(local, n, a.cache, f["id"]):
            parts.append({"f": write_blob(open(p, "rb").read()), "a": s0, "b": e})
        docs.append({
            "id": hashlib.sha256((f["id"] + "camozzi").encode()).hexdigest()[:10],
            **{k: meta.get(k, "") for k in ("arquivo", "nome", "titulo", "titulo_en", "tipo", "linha", "familia", "series", "edicao", "idioma", "resumo")},
            "nome": meta.get("nome") or meta.get("titulo", ""),
            "inch": bool(meta.get("inch")),
            "auto": auto, "drive": f["id"], "pasta": f["pasta"],
            "paginas": n, "bytes": os.path.getsize(local), "parts": parts,
            "foto": write_blob(foto) if foto else None,
            "toc": build_toc(heads, secoes), "texto": texts,
        })
        print(f"  ✓ {meta.get('nome') or meta['titulo']} — {n} páginas{' (auto)' if auto else ''}")

    # ordem natural: números antes de letras; números pelo valor
    def nkey(s):
        s = str(s or "").strip()
        m = re.match(r"(\d+)", s)
        return (0, int(m.group(1)), s.lower()) if m else (1, 0, s.lower())

    by_drive = {d["drive"]: d for d in docs}
    placed = set()
    def resolve(node):
        n = {k: node.get(k, "") for k in ("id", "titulo", "descricao", "icone")}
        ds = [by_drive[x] for x in node.get("docs", []) if x in by_drive]
        ds.sort(key=lambda d: (nkey(d["nome"]), d["inch"]))
        n["docs"] = [d["id"] for d in ds]
        placed.update(n["docs"])
        n["filhos"] = [c for c in (resolve(ch) for ch in node.get("filhos", []))]
        n["total"] = len(n["docs"]) + sum(c["total"] for c in n["filhos"])
        return n
    mapa = [resolve(x) for x in cat.get("mapa", [])]
    soltos = sorted([d for d in docs if d["id"] not in placed], key=lambda d: nkey(d["nome"]))
    if soltos:
        mapa.append({"id": "outros", "titulo": "Outros documentos", "descricao": "Documentos ainda sem seção definida.",
                     "icone": "", "docs": [d["id"] for d in soltos], "filhos": [], "total": len(soltos)})
    docs.sort(key=lambda d: nkey(d["nome"]))
    index = {"gerado": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "mapa": mapa, "docs": docs}
    index_path = write_blob(gzip.compress(json.dumps(index, ensure_ascii=False).encode()))
    config_path = write_blob(json.dumps(cat, ensure_ascii=False).encode())
    vbase = {"v": 2, "fmt": a.format, "salt": base64.b64encode(salt).decode(), "iter": it,
             "check": base64.b64encode(seal(b"camozzi-portal-ok")).decode(), "index": index_path, "config": config_path}
    absp = lambda p: os.path.abspath(os.path.join(a.out, p))
    data_files = sorted("d/" + x for x in os.listdir(os.path.join(a.out, "d")))
    SKELETON = ('<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">'
                '<meta name="robots" content="noindex,nofollow">'
                '<style>:root{color-scheme:light;box-sizing:border-box;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}'
                'body{margin:0;padding:0;font:14px -apple-system,BlinkMacSystemFont,sans-serif}img{max-width:100%}'
                '[hidden]:not([hidden=until-found i]){display:none!important}</style></head><body>\n')
    tpl = open(a.template, encoding="utf-8").read()

    # 1) portal completo (repositório -> Cloudflare Pages)
    if a.pages_dir:
        pd = a.pages_dir
        os.makedirs(os.path.join(pd, "d"), exist_ok=True)
        os.makedirs(os.path.join(pd, "src"), exist_ok=True)
        keep = set(data_files)
        for f in os.listdir(os.path.join(pd, "d")):
            if "d/" + f not in keep:
                os.remove(os.path.join(pd, "d", f))
        for p in data_files:
            dst = os.path.join(pd, p)
            if not os.path.exists(dst):
                shutil.copy(absp(p), dst)
        json.dump({**vbase, "pdfs": True}, open(os.path.join(pd, "vault.json"), "w"))
        open(os.path.join(pd, "index.html"), "w", encoding="utf-8").write(SKELETON + tpl + "\n</body></html>\n")
        shutil.copy(os.path.abspath(__file__), os.path.join(pd, "src", "build.py"))
        shutil.copy(a.template, os.path.join(pd, "src", "template.html"))
        # a configuração (com o id da pasta do Drive) só vai criptografada, em d/; nunca em texto aberto
        stale = os.path.join(pd, "src", "catalog.json")
        if os.path.exists(stale): os.remove(stale)
        open(os.path.join(pd, "_headers"), "w").write("/vault.json\n  Cache-Control: no-cache\n/index.html\n  Cache-Control: no-cache\n/\n  Cache-Control: no-cache\n/d/*\n  Cache-Control: public, max-age=31536000, immutable\n")
        print(f"Portal completo gravado em {pd}")

    # 2) painel de administração (artifact do claude.ai): sem os PDFs, só índice e configuração
    vault = {**vbase, "pdfs": False, "portal": a.portal_url}
    json.dump(vault, open(os.path.join(a.out, "vault.json"), "w"))
    shutil.copy(a.template, os.path.join(a.out, "index.html"))
    os.makedirs(os.path.join(a.out, "src"))
    shutil.copy(os.path.abspath(__file__), os.path.join(a.out, "src", "build.txt"))
    shutil.copy(a.template, os.path.join(a.out, "src", "template.txt"))
    needed = ["vault.json", "src/build.txt", "src/template.txt", index_path, config_path]
    published = set(p for p in a.published if p != "index.html")
    final = {p: absp(p) for p in needed if p not in published or not p.startswith("d/")}
    for p in sorted(published - set(needed)):
        final[p] = None
    json.dump([final], open(os.path.join(a.out, "_publish_batches.json"), "w"), indent=1)
    json.dump(needed, open(os.path.join(a.out, "_manifest.json"), "w"), indent=1)
    json.dump(pendentes, open(os.path.join(a.out, "_pendentes.json"), "w"), ensure_ascii=False, indent=1)
    total = sum(os.path.getsize(absp(p)) for p in data_files)
    print(f"Pronto: {len(docs)} documento(s), {total/1e6:.1f} MB de dados; painel: {sum(1 for v in final.values() if v)} arquivo(s) a enviar, "
          f"{sum(1 for v in final.values() if v is None)} a remover; pendentes de classificação: {len(pendentes)}")

if __name__ == "__main__":
    main()
