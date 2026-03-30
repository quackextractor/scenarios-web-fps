@echo off
setlocal

echo Starting the deployment pipeline...

:: 1. Run the Python preparation script
echo [1/3] Running Python preparation script...
python prepare_deployment.py
if %ERRORLEVEL% neq 0 (
    echo Error: Python script failed to execute.
    pause
    exit /b %ERRORLEVEL%
)

:: 2. Navigate to the deployment directory
echo [2/3] Entering deployment directory...
cd deployment
if %ERRORLEVEL% neq 0 (
    echo Error: Failed to find the deployment directory.
    pause
    exit /b %ERRORLEVEL%
)

:: 3. Run Docker Compose
echo [3/3] Starting Docker containers via Rancher Desktop...
docker compose up -d --build
if %ERRORLEVEL% neq 0 (
    echo Error: Docker Compose failed. Please ensure Rancher Desktop is running and set to use dockerd.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo Deployment successful.
echo You can access the application at http://localhost:5000
echo.
pause