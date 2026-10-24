# Portal de catálogos Camozzi

Portal interno de consulta aos catálogos técnicos, publicado pelo Cloudflare Pages.

- Os PDFs e o índice ficam **criptografados** (AES-256-GCM, chave derivada da senha de acesso). Sem a senha, os arquivos em `d/` são ilegíveis.
- `src/` guarda o gerador (`build.py`), o modelo da página e a configuração de seções.
- Atualização: botão **Sinc.** no painel de administração do claude.ai, que lê a pasta do Google Drive, gera o site e grava aqui.
