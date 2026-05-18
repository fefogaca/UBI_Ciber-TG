# Guia de testes para apresentação — TWO-HEADED-BEAST

Este documento é o **roteiro** para validarem o projeto e conduzirem a demo na defesa. Os ficheiros para enviar (PDF, texto curto, binário grande) ficam em **`help/demonstracao/`**, dentro da pasta **`help/`**: material **local** que normalmente **não é commitado** (ver `help/` no `.gitignore`). Cada membro pode gerar os ficheiros com o script ou copiar a pasta `help/` dentro da equipa.

---

## 1. Gerar material de demonstração

| Ficheiro | Uso na demo |
|----------|-------------|
| `amostra_texto_curta.txt` | Envio rápido, verificar conteúdo e hash |
| `amostra_apresentacao.html` | Abrir no browser; se não houver PDF, **Imprimir → Guardar como PDF** |
| `amostra_apresentacao.pdf` | Gerado automaticamente se o **Google Chrome** estiver instalado (modo headless) |
| `amostra_binaria_16mb.bin` | ~16 MiB para ver **vários blocos** (limiar 12 MiB no payload) |

Se o PDF não for gerado (sem Chrome), abram o `.html` e exportem PDF manualmente.

---

## 2. Antes de cada sessão de testes (Mac e Windows)

1. Mesmo **commit** / mesma pasta do projeto em ambos os PCs.
2. `python -m venv .venv` e `pip install -r requirements.txt` onde ainda não existir.
3. Anotar **IPv4** de cada máquina na LAN (`ipconfig` no Windows; definições de rede / `ifconfig` no Mac).
4. Escolher **porta** (ex.: `9000`) e abrir **firewall** no **receptor** para essa porta TCP.
5. Definir mentalmente os placeholders abaixo (ou copiar para um post-it):

- `WIN_IP` — IPv4 do Windows  
- `MAC_IP` — IPv4 do Mac  
- `PORT` — ex.: `9000`  

**Regra de ouro:** em cada teste, `serve` e `send` usam os **mesmos** `--cipher`, `--hash`, `--compress` e `--no-encrypt`.

---

## 3. Roteiro sugerido na apresentação (ordem)

1. **Contexto** (30 s): dois processos, TCP, KEX X25519, fingerprint `[KEY FINGERPRINT]`.
2. **Smoke local** num portátil: `127.0.0.1` + ficheiro pequeno → OK.
3. **LAN real**: Windows recebe / Mac envia (ou o contrário) com **defaults** → mostrar ficheiro recebido + mesmo tamanho/hash.
4. **Uma variação forte**: ChaCha20 **ou** `--compress` **ou** `--no-encrypt` (escolher uma para não alongar).
5. **Blocos grandes**: enviar `help/demonstracao/amostra_binaria_16mb.bin` → mencionar linhas `Block` no terminal.
6. **Negativo**: propositadamente **compressão só num dos lados** → erro **visível nos dois** terminais.
7. **Opcional tempo permitido**: assinatura (`private.pem` / `public.pem`) ou modo **`menu`**.

---

## 4. Comandos — smoke local (cada máquina)

**Terminal A — serve:**

```bash
python -m src serve --host 127.0.0.1 --port 9000 --output-dir ./received
```

**Terminal B — send:**

```bash
python -m src send --host 127.0.0.1 --port 9000 --file ./help/demonstracao/amostra_texto_curta.txt
```

(Ajusta o caminho se não geraste ainda `help/demonstracao/` — corre `python help/scripts/gerar_material_demo.py`.)

**Ajuda / menu:**

```bash
python -m src --help
python -m src menu
```

---

## 5. Windows recebe, Mac envia (substituir `WIN_IP`)

**Windows — serve:**

```bash
python -m src serve --host 0.0.0.0 --port 9000 --output-dir ./received
```

**Mac — send (baseline):**

```bash
python -m src send --host WIN_IP --port 9000 --file ./help/demonstracao/amostra_apresentacao.pdf
```

### 5.1 Com compressão (ambos com `--compress`)

**Windows:**

```bash
python -m src serve --host 0.0.0.0 --port 9000 --output-dir ./received --compress
```

**Mac:**

```bash
python -m src send --host WIN_IP --port 9000 --file ./help/demonstracao/amostra_apresentacao.pdf --compress
```

### 5.2 AES-128-GCM

**Windows:**

```bash
python -m src serve --host 0.0.0.0 --port 9000 --output-dir ./received --cipher AES-128-GCM
```

**Mac:**

```bash
python -m src send --host WIN_IP --port 9000 --file ./help/demonstracao/amostra_texto_curta.txt --cipher AES-128-GCM
```

### 5.3 ChaCha20-Poly1305

**Windows:**

```bash
python -m src serve --host 0.0.0.0 --port 9000 --output-dir ./received --cipher CHACHA20-POLY1305
```

**Mac:**

```bash
python -m src send --host WIN_IP --port 9000 --file ./help/demonstracao/amostra_apresentacao.pdf --cipher CHACHA20-POLY1305
```

### 5.4 Hash SHA384 ou SHA512

**Windows (SHA384):**

```bash
python -m src serve --host 0.0.0.0 --port 9000 --output-dir ./received --hash SHA384
```

**Mac:**

```bash
python -m src send --host WIN_IP --port 9000 --file ./help/demonstracao/amostra_texto_curta.txt --hash SHA384
```

(Repetir com `SHA512` nos dois lados.)

### 5.5 Só HMAC (`--no-encrypt`) — sem passar `--cipher`

**Windows:**

```bash
python -m src serve --host 0.0.0.0 --port 9000 --output-dir ./received --no-encrypt
```

**Mac:**

```bash
python -m src send --host WIN_IP --port 9000 --file ./help/demonstracao/amostra_texto_curta.txt --no-encrypt
```

### 5.6 Ficheiro grande (blocos)

**Windows:**

```bash
python -m src serve --host 0.0.0.0 --port 9000 --output-dir ./received
```

**Mac:**

```bash
python -m src send --host WIN_IP --port 9000 --file ./help/demonstracao/amostra_binaria_16mb.bin
```

### 5.7 Assinatura digital (chaves na pasta actual)

Gerar uma vez (OpenSSL):

```bash
openssl ecparam -name prime256v1 -genkey -noout -out private.pem
openssl ec -in private.pem -pubout -out public.pem
```

**Windows:**

```bash
python -m src serve --host 0.0.0.0 --port 9000 --output-dir ./received --verify-key ./public.pem
```

**Mac:**

```bash
python -m src send --host WIN_IP --port 9000 --file ./help/demonstracao/amostra_apresentacao.pdf --sign-key ./private.pem
```

### 5.8 Servidor uma só receção (`--once`)

**Windows:**

```bash
python -m src serve --host 0.0.0.0 --port 9000 --output-dir ./received --once
```

**Mac:**

```bash
python -m src send --host WIN_IP --port 9000 --file ./help/demonstracao/amostra_texto_curta.txt
```

### 5.9 Silencioso (`-q`)

**Windows:**

```bash
python -m src serve --host 0.0.0.0 --port 9000 --output-dir ./received -q
```

**Mac:**

```bash
python -m src send --host WIN_IP --port 9000 --file ./help/demonstracao/amostra_texto_curta.txt -q
```

---

## 6. Mac recebe, Windows envia (substituir `MAC_IP`)

**Mac — serve:**

```bash
python -m src serve --host 0.0.0.0 --port 9000 --output-dir ./received
```

**Windows — send (PowerShell, caminhos com `.\`):**

```powershell
python -m src send --host MAC_IP --port 9000 --file .\help\demonstracao\amostra_apresentacao.pdf
```

Repetir as variantes da secção 5 trocando apenas o comando `send` para usar `MAC_IP` e caminhos Windows.

---

## 7. Testes negativos (erro em ambos os lados)

### 7.1 Compressão mismatched

**Serve** sem `--compress`, **send** com `--compress` (ou o contrário). Esperado: falha com mensagens nos dois terminais.

### 7.2 Cifra mismatched

**Serve:**

```bash
python -m src serve --host 0.0.0.0 --port 9000 --output-dir ./received --cipher AES-256-GCM
```

**Send:**

```bash
python -m src send --host RECEIVER_IP --port 9000 --file ./help/demonstracao/amostra_texto_curta.txt --cipher CHACHA20-POLY1305
```

(`RECEIVER_IP` = IP da máquina onde corre o `serve`.)

### 7.3 Hash mismatched

**Serve:** `--hash SHA256` · **Send:** `--hash SHA512` (restante igual).

---

## 8. Verificar integridade do ficheiro

**Mac:**

```bash
shasum -a 256 ./help/demonstracao/amostra_texto_curta.txt ./received/amostra_texto_curta.txt
```

**Windows (PowerShell):**

```powershell
Get-FileHash .\help\demonstracao\amostra_texto_curta.txt -Algorithm SHA256
Get-FileHash .\received\amostra_texto_curta.txt -Algorithm SHA256
```

---

## 9. Modo interativo (`menu`)

```bash
python -m src menu
```

Sugestão na demo: mostrar **Receber** com rede LAN, depois **Enviar** usando destino guardado; referir **gestão de destinos** e **TOFU fingerprint** conforme o README principal.

---

## 10. Checklist mínimo “está conforme”

- [ ] Transferência LAN bem-sucedida nos **dois sentidos** (Mac↔Windows).
- [ ] Pelo menos **duas** combinações distintas (ex.: default + ChaCha ou + compress).
- [ ] Caso `--no-encrypt` a funcionar.
- [ ] Caso **ficheiro grande** com vários blocos visíveis no log.
- [ ] Pelo menos **um** teste negativo com erro **nos dois** lados.
- [ ] **Fingerprint** igual nos dois terminais numa ligação honesta (referência MITM se perguntarem).

---

## 11. Nota sobre Git

- O **código da aplicação** em `src/` (e ficheiros do projecto como `README.md`) é o que se publica no repositório.
- A pasta **`help/`** está no **`.gitignore`**: o guia (`help/docs/...`), o script (`help/scripts/...`) e os ficheiros gerados em `help/demonstracao/` **não entram** em `git push`. Partilhem a pasta `help/` dentro da equipa (zip, drive, etc.) ou gerem localmente com `python help/scripts/gerar_material_demo.py`.
- **`Enunciado.md`** no `.gitignore`: se já tinha sido commitado antes, é preciso **uma vez** `git rm --cached Enunciado.md` e commitar — o ficheiro continua no disco, mas deixa de ser rastreado.
