@echo off
echo Starting packet sniffer...
"C:\Python312\python.exe" script.py
echo.
echo If window closed immediately, check logs/error.log for details
echo Press any key to close this window
pause > nul
