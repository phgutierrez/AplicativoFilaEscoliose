@echo off
echo ===== Instalando dependencias =====
pip install -r requirements.txt --only-binary=numpy,pandas

echo.
echo ===== Iniciando aplicacao Flask =====
set FLASK_APP=app.py
set FLASK_ENV=production
python -m flask run --host=0.0.0.0 --port=5000

pause