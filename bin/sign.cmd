@echo off

if "%PFX_FILE%"=="" set /p PFX_FILE=PFX File: 
if "%DEMO_FILE%"=="" set /p DEMO_FILE=File to sign: 
@echo on
signtool sign /f %PFX_FILE% /fd SHA256 /t http://timestamp.digicert.com /v %DEMO_FILE%
@echo off
