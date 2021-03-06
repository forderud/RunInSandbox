@echo off
echo NOTICE: Script MUST be run as Administrator.
:: Errors from "reg" tool are muted to avoid flooding the build log with errors from already deleted registry entries.

:: Fix issue with "Run as Administrator" current dir
setlocal enableextensions
cd /d "%~dp0"


:: Remove all traces of TestControl from registry (except progid)
for %%R in (HKEY_LOCAL_MACHINE HKEY_CURRENT_USER) do (
  :: TypeLib & AppID
  reg delete "%%R\SOFTWARE\Classes\TypeLib\{1FC81ABC-F123-4DEE-9380-4B40032E0ACD}" /f 2> NUL
  reg delete "%%R\SOFTWARE\Classes\AppID\{264FBADA-8FEF-44B7-801E-B728A1749B5A}"   /f 2> NUL
  
  for %%P in (32 64) do (
    :: TestControl class
    reg delete "%%R\SOFTWARE\Classes\CLSID\{F0DFBE77-1697-428E-A895-EFEE202B9333}"     /f /reg:%%P 2> NUL
    reg delete "%%R\SOFTWARE\Classes\Interface\{570FBF3C-D853-435E-B761-6A264393B9DA}" /f /reg:%%P 2> NUL
  )
)

::pause
