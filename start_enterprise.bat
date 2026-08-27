@echo off
TITLE CryptoJackGuard Enterprise Server
echo Starting FastAPI Cloud Backend...
start cmd /k ".venv\Scripts\python.exe -m uvicorn src.backend.main:app --reload"
timeout /t 3
echo Starting Streamlit Enterprise Dashboard...
start cmd /k ".venv\Scripts\python.exe -m streamlit run dashboard_app.py"
echo Enterprise System is fully up and running!
