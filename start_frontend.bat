@echo off
echo ========================================
echo  AI Phishing Website Detector - Frontend
echo ========================================
echo.
echo Starting React/Vite frontend on http://localhost:5173
echo Make sure backend is running on port 8000 first.
echo Press Ctrl+C to stop the server.
echo.
cd /d "%~dp0frontend"
npm run dev
pause
