@echo off
setlocal
if exist "%~dp0..\.venv-win\Scripts\python.exe" goto venv
where py >nul 2>&1
if not errorlevel 1 goto py
echo Python 3.9+ gerekli. WINDOWS.md dosyasina bakin.
exit /b 1
:venv
"%~dp0..\.venv-win\Scripts\python.exe" "%~dp0launcher.py" %*
exit /b %errorlevel%
:py
py -3 "%~dp0launcher.py" %*
exit /b %errorlevel%
