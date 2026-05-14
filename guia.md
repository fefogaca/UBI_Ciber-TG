# Guia: teste de transferência Mac (emissor) → Windows (receptor)

Ambos os computadores devem estar na **mesma rede local** (mesmo Wi‑Fi ou Ethernet ao mesmo router). Este guia assume que o **Windows recebe** (`serve`) e o **Mac envia** (`send`).

**Alternativa:** em ambos os sistemas podes usar o modo guiado `python -m thb menu` (menus, IP guardados em `~/.thb/peers.json`). Os passos abaixo continuam válidos para linha de comando direta.

---

## Pré-requisito comum

- Ter o **mesmo projeto** `thb` nas duas máquinas (cópia por USB, AirDrop da pasta, Git, etc.).
- **Python 3** instalado em ambos.
- Os comandos **`serve` e `send` devem usar exatamente os mesmos** `--cipher`, `--hash`, `--compress` e `--no-encrypt`. Nos exemplos abaixo usamos só os valores por omissão (cifrado AES-256-GCM, SHA256, sem compressão extra).

---

## Parte A — Windows (receptor)

### A1. Instalar Python

1. Descarregar o instalador em [python.org/downloads](https://www.python.org/downloads/windows/).
2. Durante a instalação, ativar **“Add python.exe to PATH”** se a opção existir.

### A2. Abrir terminal na pasta do projeto

No **PowerShell** ou **Prompt de Comandos**:

```text
cd "C:\caminho\completo\para\Trabalho em Grupo"
```

(Ajusta o caminho para onde copiaste o projeto.)

### A3. Ambiente virtual e dependências

```text
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Se `python` não for reconhecido, experimenta `py -m venv .venv` e `py -m pip install -r requirements.txt`.

### A4. Firewall — permitir a porta TCP

O `serve` escuta numa porta (ex.: **9000**). O Firewall do Windows pode bloquear ligações vindas do Mac.

1. **Painel de controlo** → **Firewall do Windows** → **Definições avançadas**.
2. **Regras de entrada** → **Nova regra**.
3. Tipo: **Porta** → **TCP** → **Portas locais específicas**: `9000` (ou a porta que fores usar).
4. Ação: **Permitir a ligação**.
5. Perfis: marca pelo menos **Privado** (rede doméstica).
6. Nome: ex. `THB TCP 9000`.

### A5. Descobrir o endereço IPv4 do Windows

No PowerShell:

```text
ipconfig
```

Anota o **Endereço IPv4** da placa em uso (Wi‑Fi ou Ethernet), por exemplo `192.168.1.45`. **Esse** valor vais usar no Mac em `--host`.

### A6. Iniciar o servidor (receptor)

**Importante:** usar `--host 0.0.0.0` para aceitar ligações **da rede**, não só do próprio PC.

Com o venv ativo (`(.venv)` visível na linha de comando):

```text
python -m thb serve --host 0.0.0.0 --port 9000 --output-dir .\received
```

Mantém este terminal aberto até o envio terminar. O ficheiro recebido aparece em `received\` com o **mesmo nome** do ficheiro enviado.

---

## Parte B — Mac (emissor)

### B1. Ir à pasta do projeto e ativar o venv

No **Terminal** (ajusta o `cd` para a pasta real onde está o projeto):

```bash
cd "/Users/teuuser/.../Trabalho em Grupo"
source .venv/bin/activate
```

Se ainda não tiveres o venv no Mac:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### B2. Enviar o ficheiro (ex.: imagem)

Substitui `192.168.x.x` pelo **IPv4 do Windows** (passo A5) e ajusta o caminho do ficheiro:

```bash
python -m thb send --host 192.168.x.x --port 9000 --file "/Users/teuuser/Imagens/foto.png"
```

Exemplo se o Windows for `192.168.1.45`:

```bash
python -m thb send --host 192.168.1.45 --port 9000 --file "/Users/teuuser/Imagens/foto.png"
```

No Windows, confirma em `received\foto.png` (ou o nome que tenha o ficheiro).

---

## Exemplo com compressão (opcional)

**Windows:**

```text
python -m thb serve --host 0.0.0.0 --port 9000 --output-dir .\received --compress
```

**Mac:**

```bash
python -m thb send --host 192.168.x.x --port 9000 --file "/caminho/imagem.png" --compress
```

## Exemplo com outra cifra (opcional)

Os dois lados **iguais**, por exemplo ChaCha20-Poly1305:

**Windows:**

```text
python -m thb serve --host 0.0.0.0 --port 9000 --output-dir .\received --cipher CHACHA20-POLY1305
```

**Mac:**

```bash
python -m thb send --host 192.168.x.x --port 9000 --file "/caminho/imagem.png" --cipher CHACHA20-POLY1305
```

---

## Envio assinado (opcional)

Gera par de chaves no Windows ou no Mac (OpenSSL) e copia os PEM. Exemplo mínimo:

**Windows (PowerShell)** — receptor com chave pública:

```text
python -m thb serve --host 0.0.0.0 --port 9000 --output-dir .\received --verify-key C:\caminho\public.pem
```

**Mac** — emissor com chave privada:

```bash
python -m thb send --host 192.168.x.x --port 9000 --file "/caminho/imagem.png" --sign-key /caminho/private.pem
```

---

## Resolução de problemas

| Problema | O que verificar |
|----------|-----------------|
| No Mac: timeout ou “Connection refused” | Windows tem o `serve` a correr; `--host 0.0.0.0`; firewall com porta **9000** aberta; IPv4 correto. |
| “Failed to decrypt transfer header” / mismatch | Os dois comandos têm de ter os **mesmos** flags de cifra/hash/compress/no-encrypt. |
| IPv4 errado | No Windows, confirma com `ipconfig` qual a interface ativa (Wi‑Fi vs cabo). |
| Porta ocupada | Muda `--port` nos **dois** lados (ex. 9001) e abre essa porta no firewall. |

---

## Nota sobre tipos de ficheiro

Podes enviar **qualquer ficheiro** (imagem `.png`/`.jpg`, PDF, ZIP, etc.). O programa trata tudo como bytes; não é necessário ser ficheiro de texto.
