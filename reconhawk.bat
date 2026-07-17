@echo off
REM ReconHawk launcher for Windows. Double-click to run.
cd /d "%~dp0"

REM Try the py launcher, then python on PATH, then a common install path.
py -3 reconhawk.py %* 2>nul
if %errorlevel%==0 goto :eof

python reconhawk.py %*
if %errorlevel%==0 goto :eof

"%LocalAppData%\Programs\Python\Python312\python.exe" reconhawk.py %*
if %errorlevel% neq 0 (
    echo.
    echo Could not find Python. Install it from https://python.org and run:
    echo     pip install -r requirements.txt
    pause
)
