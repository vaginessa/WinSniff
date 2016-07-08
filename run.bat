@echo off
SETLOCAL ENABLEDELAYEDEXPANSION
:: delimiter
SET DELIMITER=%1
SET DATESTRING=%date:~-10,2%%DELIMITER%%date:~-7,2%%DELIMITER%%date:~-4,4%
SET TIMESTRING=%TIME%
:: trim last 3 characters
set TIMESTRING=%TIMESTRING:~0,-3%
SET TIMESTRING=%TIMESTRING::=!DELIMITER!%
java -cp .;jnetpcap.jar Sniffer > %DATESTRING%_%TIMESTRING: =0%_sniff.log
:: optional java -cp .;jnetpcap.jar Sniffer
pause
