@echo off
cd /d "%~dp0"
start "Secure Log SIEM Server" cmd /k "venv\Scripts\activate.bat && uvicorn app.main:app --reload --port 8001"
timeout /t 4 /nobreak >nul
start http://localhost:8001/docs
echo Server sudah jalan di window baru. Window ini boleh ditutup.
pause