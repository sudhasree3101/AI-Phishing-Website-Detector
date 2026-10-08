@echo off
echo ========================================
echo  AI Phishing Website Detector - Backend
echo ========================================
echo.
echo Starting FastAPI backend on http://localhost:8000
echo Press Ctrl+C to stop the server.
echo.
cd /d "%~dp0backend"
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
pause
