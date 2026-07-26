@echo off
cd /d "%~dp0"
call venv\Scripts\activate.bat

for /f "tokens=2 delims==" %%A in ('findstr "INGEST_API_KEY" .env') do set APIKEY=%%A

if "%APIKEY%"=="" (
    echo Tidak ketemu INGEST_API_KEY di .env
    pause
    exit /b 1
)

python scripts\seed_demo_data.py --base-url http://localhost:8001 --api-key "%APIKEY%"
pause