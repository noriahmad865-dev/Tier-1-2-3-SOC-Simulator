@echo off
cd /d "%~dp0"
echo [*] Starting Tier 1 SOC Operations Center...
".venv\Scripts\python.exe" soc_gui.py
pause