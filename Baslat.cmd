@echo off
call "%~dp0windows\entry.cmd" --mode run %*
if errorlevel 1 pause
