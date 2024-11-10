@echo off
REM Ensure Docker is running
echo Checking Docker...
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo Docker is not running. Please start Docker Desktop.
    exit /b 1
)

REM Check if the Docker image exists
docker images master-postgres >nul 2>&1
if %errorlevel% neq 0 (
    echo Docker image not found. Pulling image...
    docker pull magdalenacode/masterthesis:latest
)

REM Check if the Docker container is already running
docker inspect -f "{{.State.Running}}" master-postgres 2>nul | findstr /R /C:"true" >nul
if %errorlevel% neq 0 (
    REM Start Docker container
    echo Starting Docker container...
    docker run --rm --name master-postgres -e POSTGRES_PASSWORD=postgres -p 5432:5432 -d magdalenacode/masterthesis:latest
)

REM Initialize Database (No output)
echo Initializing Database...
set PROJECT_DIR=%~dp0
cd /d "%PROJECT_DIR%dashboard_backend"
call .venv\Scripts\activate
python Initialize_Database.py >nul 2>&1

REM Start API
echo Starting API...
cd /d "%PROJECT_DIR%dashboard_backend"
REM Ensure the virtual environment is still active
if not defined VIRTUAL_ENV (
    call .venv\Scripts\activate
)
start /B python API.py > api.log 2>&1

REM Start Data Scanner
echo Starting Data Scanner...
cd /d "%PROJECT_DIR%dashboard_backend"
call .venv\Scripts\activate
start /B python Insert_Real_Data.py > data_scanner.log 2>&1

REM Start Frontend
echo Starting Frontend...
cd /d "%PROJECT_DIR%frontend"
start /B npm run dev > frontend.log 2>&1

echo All services started, check the logs if an issue occurs
echo Access the API-Security-Analysis-Dashboard here: http://localhost:5173/
echo Access the API Documentation here: http://localhost:5000/apidocs/.
