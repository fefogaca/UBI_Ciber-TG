#!/usr/bin/env bash
# Atalho de execução — macOS / Linux.
# Cria o venv na primeira utilização, instala dependências e invoca python -m src.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "Erro: Python não encontrado (instala python3)." >&2
  exit 1
fi

if [[ ! -d .venv ]]; then
  "$PY" -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

pip install -q -r requirements.txt
exec python -m src "$@"
