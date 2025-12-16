@echo off
REM GhidraMCP Headless Launcher for Windows
REM 
REM This script launches GhidraMCP in headless mode using Ghidra's analyzeHeadless.
REM
REM Usage:
REM   launch_headless.bat <ghidra_install_dir> <project_location> <project_name> <file_to_analyze>
REM
REM Example:
REM   launch_headless.bat "C:\ghidra_11.2.1" "C:\projects\myproject" "MyProject" "target.exe"
REM
REM Environment Variables:
REM   GHIDRAMCP_PORT - Port for HTTP server (default: 8192)
REM   GHIDRAMCP_KEEP_RUNNING - Keep server running after analysis (default: true)
REM   GHIDRA_INSTALL_DIR - Ghidra installation directory (overrides first argument)

setlocal enabledelayedexpansion

REM Check if help is requested
if "%1"=="--help" goto :show_help
if "%1"=="-h" goto :show_help
if "%1"=="/?" goto :show_help

REM Get Ghidra installation directory
if defined GHIDRA_INSTALL_DIR (
    set "GHIDRA_DIR=%GHIDRA_INSTALL_DIR%"
    echo Using GHIDRA_INSTALL_DIR from environment: !GHIDRA_DIR!
    REM All arguments are shifted - first arg is project location
    set "PROJECT_LOCATION=%~1"
    set "PROJECT_NAME=%~2"
    set "FILE_TO_ANALYZE=%~3"
) else if not "%1"=="" (
    set "GHIDRA_DIR=%~1"
    REM Arguments start from second position
    set "PROJECT_LOCATION=%~2"
    set "PROJECT_NAME=%~3"
    set "FILE_TO_ANALYZE=%~4"
) else (
    echo ERROR: Ghidra installation directory not specified
    echo.
    goto :show_help
)

REM Validate Ghidra directory
if not exist "!GHIDRA_DIR!\support\analyzeHeadless.bat" (
    echo ERROR: Invalid Ghidra installation directory: !GHIDRA_DIR!
    echo Could not find analyzeHeadless.bat
    exit /b 1
)

echo Ghidra directory: !GHIDRA_DIR!

REM Validate arguments
if "!PROJECT_LOCATION!"=="" (
    echo ERROR: Project location not specified
    goto :show_help
)

if "!PROJECT_NAME!"=="" (
    echo ERROR: Project name not specified
    goto :show_help
)

if "!FILE_TO_ANALYZE!"=="" (
    echo ERROR: File to analyze not specified
    goto :show_help
)

REM Validate file exists
if not exist "!FILE_TO_ANALYZE!" (
    echo ERROR: File not found: !FILE_TO_ANALYZE!
    exit /b 1
)

REM Set default environment variables if not set
if not defined GHIDRAMCP_PORT (
    set "GHIDRAMCP_PORT=8192"
    echo Using default port: !GHIDRAMCP_PORT!
) else (
    echo Using GHIDRAMCP_PORT from environment: !GHIDRAMCP_PORT!
)

if not defined GHIDRAMCP_KEEP_RUNNING (
    set "GHIDRAMCP_KEEP_RUNNING=true"
)

REM Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"

REM Set script path - check environment variable first, then Ghidra scripts directory
if defined GHIDRAMCP_SCRIPT_PATH (
    set "SCRIPT_PATH=%GHIDRAMCP_SCRIPT_PATH%"
) else (
    set "SCRIPT_PATH=!GHIDRA_DIR!\Ghidra\Features\Base\ghidra_scripts"
)

REM Display which script path is being used
if defined GHIDRAMCP_SCRIPT_PATH (
    echo Using GHIDRAMCP_SCRIPT_PATH from environment: !SCRIPT_PATH!
) else (
    echo Using Ghidra scripts directory: !SCRIPT_PATH!
)

REM Validate script exists
set "SCRIPT_FILE=!SCRIPT_PATH!\GhidraMCPHeadlessServer.java"

REM Use dir to check if file exists
dir "!SCRIPT_FILE!" >nul 2>&1
set "FILE_CHECK_RESULT=!ERRORLEVEL!"
if "!FILE_CHECK_RESULT!"=="0" goto :script_found

echo ERROR: GhidraMCPHeadlessServer.java not found in: !SCRIPT_PATH!
echo.
echo Please ensure the script is available:
echo   1. Copy GhidraMCPHeadlessServer.java to: !GHIDRA_DIR!\Ghidra\Features\Base\ghidra_scripts\
echo   2. Or copy to your user ghidra_scripts directory
echo   3. Or set GHIDRAMCP_SCRIPT_PATH environment variable to the script location
echo.
echo The simplified script is located at: GhidraMCPHeadlessServer.java
exit /b 1

:script_found
echo Script found: !SCRIPT_FILE!

echo.
echo ===========================================
echo GhidraMCP Headless Launcher
echo ===========================================
echo Ghidra: !GHIDRA_DIR!
echo Project: !PROJECT_LOCATION!\!PROJECT_NAME!
echo File: !FILE_TO_ANALYZE!
echo Port: !GHIDRAMCP_PORT!
echo Keep Running: !GHIDRAMCP_KEEP_RUNNING!
echo Script Path: !SCRIPT_PATH!
echo ===========================================
echo.

echo Starting Ghidra analyzeHeadless...
echo.

"!GHIDRA_DIR!\support\analyzeHeadless.bat" ^
    "!PROJECT_LOCATION!" "!PROJECT_NAME!" ^
    -import "!FILE_TO_ANALYZE!" ^
    -scriptPath "!SCRIPT_PATH!" ^
    -postScript GhidraMCPHeadlessServer.java

exit /b !ERRORLEVEL!

:show_help
echo.
echo GhidraMCP Headless Launcher for Windows
echo.
echo Usage:
echo   %~nx0 [ghidra_dir] ^<project_location^> ^<project_name^> ^<file_to_analyze^>
echo.
echo Arguments:
echo   ghidra_dir        - Ghidra installation directory (optional if GHIDRA_INSTALL_DIR is set)
echo   project_location  - Directory containing the Ghidra project
echo   project_name      - Name of the Ghidra project (will be created if doesn't exist)
echo   file_to_analyze   - Binary file to import and analyze
echo.
echo Environment Variables:
echo   GHIDRA_INSTALL_DIR      - Ghidra installation directory (overrides ghidra_dir argument)
echo   GHIDRAMCP_PORT          - HTTP server port (default: 8192)
echo   GHIDRAMCP_KEEP_RUNNING  - Keep server running after analysis (default: true)
echo   GHIDRAMCP_SCRIPT_PATH   - Path to directory containing GhidraMCPHeadlessServer.java
echo                             (default: GHIDRA_DIR\Ghidra\Features\Base\ghidra_scripts)
echo.
echo Requirements:
echo   - GhidraMCPHeadlessServer.java must be in the scripts directory
echo.
echo Examples:
echo   %~nx0 "C:\ghidra_11.2.1" "C:\projects" "MyProject" "target.exe"
echo.
echo   set GHIDRA_INSTALL_DIR=C:\ghidra_11.2.1
echo   set GHIDRAMCP_PORT=9000
echo   %~nx0 "C:\projects" "MyProject" "target.exe"
echo.
echo   REM If script is in a custom location:
echo   set GHIDRAMCP_SCRIPT_PATH=C:\my_scripts
echo   %~nx0 "C:\ghidra_11.2.1" "C:\projects" "MyProject" "target.exe"
echo.
exit /b 1
