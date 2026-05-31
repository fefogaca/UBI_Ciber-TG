@echo off
setlocal EnableExtensions
cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
  echo Erro: Python nao encontrado no PATH.
  exit /b 1
)

if not exist ".venv" (
  python -m venv .venv
)

call ".venv\Scripts\activate.bat"
pip install -q -r requirements.txt
python -m src %*
