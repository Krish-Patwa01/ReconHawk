@echo off
REM PersonaX launcher - runs personax.py with the bundled Python, passing all args.
REM Usage from this folder:  personax <username> [options]
"C:\Users\kpatw\AppData\Local\Programs\Python\Python312\python.exe" "%~dp0personax.py" %*
