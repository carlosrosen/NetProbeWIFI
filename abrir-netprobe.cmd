@echo off
setlocal
pushd "%~dp0" || exit /b 1
set "NETPROBE_PYTHON_CHECK=import sys, sysconfig; sys.exit(sys.version_info < (3, 10) or 'mingw' in sysconfig.get_platform())"

if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -E -c "%NETPROBE_PYTHON_CHECK%" >nul 2>&1
    if not errorlevel 1 goto local
)
py -3 -E -c "%NETPROBE_PYTHON_CHECK%" >nul 2>&1
if not errorlevel 1 goto py
python -E -c "%NETPROBE_PYTHON_CHECK%" >nul 2>&1
if not errorlevel 1 goto python
where uv >nul 2>&1
if not errorlevel 1 goto uv

echo Instale o Python 3.10 ou superior para Windows e execute este arquivo novamente.
popd
exit /b 1

:local
".venv\Scripts\python.exe" -E -X utf8 main.py
goto fim

:py
py -3 -E -X utf8 main.py
goto fim

:python
python -E -X utf8 main.py
goto fim

:uv
set "UV_PYTHON_INSTALL_DIR=%CD%\env\cpython"
set "UV_CACHE_DIR=%CD%\env\uv-cache"
uv python install 3.12 --no-bin --no-registry
if errorlevel 1 goto fim
uv venv --python 3.12 --managed-python --no-python-downloads --allow-existing .venv
if errorlevel 1 goto fim
goto local

:fim
set "NETPROBE_EXIT=%errorlevel%"
popd
exit /b %NETPROBE_EXIT%
