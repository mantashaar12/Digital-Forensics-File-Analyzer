@echo off
title Digital Forensics File Analyzer
cd /d "%~dp0"
if not exist "venv\Scripts\python.exe" (
    echo ERROR: venv folder not found in this folder.
    echo Create it once with:  python -m venv venv
    echo Then run:  venv\Scripts\python.exe -m pip install -r requirements.txt
    pause
    exit /b 1
)
echo Starting Digital Forensics File Analyzer...
echo The browser will open at http://localhost:8501
echo Keep this window open while using the app. Press Ctrl+C to stop.
venv\Scripts\python.exe -m streamlit run digital_forensics_analyzer_pro.py --browser.gatherUsageStats false
pause