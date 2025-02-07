@echo off
cd /d %~dp0
call D:\software\VisualStudio\ms\versions\2022\Community\Common7\Tools\VsDevCmd.bat

set PFX_FILE=%USERPROFILE%\OneDrive\self_cert\chcs.pfx
set DEMO_FILE=%1


sign
