@echo off
setlocal
cd /d "%~dp0"

if not exist .venv (
  python -m venv .venv
)

call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt

if not exist knowledge_base mkdir knowledge_base
if not exist vector_store mkdir vector_store
if not exist uploads mkdir uploads
if not exist logs mkdir logs
if not exist reports mkdir reports

streamlit run streamlit_app.py
