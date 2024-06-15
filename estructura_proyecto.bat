@echo off

set "BASE_DIR=gapo_login"
set "APP_DIR=%BASE_DIR%\app"

set "CORE_DIR=%APP_DIR%\core"

set "DB_DIR=%APP_DIR%\db"

set "SCHEMAS_DIR=%APP_DIR%\schemas"

set "UTILS_DIR=%APP_DIR%\utils"

set "QA_DIR=%BASE_DIR%\QA"
set "VENV_DIR=%BASE_DIR%\venv"


mkdir %BASE_DIR%
mkdir %APP_DIR%
mkdir %CORE_DIR%
mkdir %DB_DIR%
mkdir %SCHEMAS_DIR%
mkdir %UTILS_DIR%
mkdir %QA_DIR%
mkdir %VENV_DIR%


echo. > %BASE_DIR%\.env
echo. > %BASE_DIR%\.gitignore
echo. > %BASE_DIR%\main.py
echo. > %BASE_DIR%\requirements.txt
echo. > %CORE_DIR%\config.py
echo. > %CORE_DIR%\security.py
echo. > %DB_DIR%\database.py

echo Estructura de proyecto creada exitosamente.
