@echo off
REM GhidraMCP Headless Launcher for Existing Projects
REM 
REM This script launches GhidraMCP in headless mode on an EXISTING Ghidra project.
REM
REM Usage:
REM   launch_headless_existing.bat <project_path_with_.gpr> [program_name]
REM
REM Example:
REM   launch_headless_existing.bat "C:\Dev\Ghidra\Projects\MyProject\MyProject.gpr"
REM   launch_headless_existing.bat "C:\Dev\Ghidra\Projects\MyProject\MyProject.gpr" "malware.exe"
REM
REM Environment Variables:
REM   GHIDRAMCP_PORT - Port for HTTP server (default: 8192)
REM   GHIDRAMCP_KEEP_RUNNING - Keep server running after script (default: true)
REM   GHIDRA_INSTALL_DIR - Ghidra installation directory (required)

setlocal enabledelayedexpansion

REM Check if help is requested
if "%1"=="--help" goto :show_help
if "%1"=="-h" goto :show_help
if "%1"=="/?" goto :show_help

REM Get Ghidra installation directory from environment
if not defined GHIDRA_INSTALL_DIR (
    echo ERROR: GHIDRA_INSTALL_DIR environment variable not set
    echo.
    goto :show_help
)

set "GHIDRA_DIR=%GHIDRA_INSTALL_DIR%"
echo Using GHIDRA_INSTALL_DIR: !GHIDRA_DIR!

REM Validate Ghidra directory
if not exist "!GHIDRA_DIR!\support\analyzeHeadless.bat" (
    echo ERROR: Invalid Ghidra installation directory: !GHIDRA_DIR!
    echo Could not find analyzeHeadless.bat
    exit /b 1
)

REM Get the .gpr file path
set "GPR_FILE=%~1"
set "PROGRAM_NAME=%~2"

REM Validate .gpr file argument
if "!GPR_FILE!"=="" (
    echo ERROR: Project .gpr file not specified
    goto :show_help
)

REM Validate .gpr file exists
if not exist "!GPR_FILE!" (
    echo ERROR: Project file not found: !GPR_FILE!
    exit /b 1
)

REM Extract project location and name from .gpr path
for %%F in ("!GPR_FILE!") do (
    set "PROJECT_LOCATION=%%~dpF"
    set "PROJECT_NAME=%%~nF"
)

REM Remove trailing backslash from project location
if "!PROJECT_LOCATION:~-1!"=="\" set "PROJECT_LOCATION=!PROJECT_LOCATION:~0,-1!"

echo Project Location: !PROJECT_LOCATION!
echo Project Name: !PROJECT_NAME!

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

REM Set script path - check environment variable first
if defined GHIDRAMCP_SCRIPT_PATH (
    set "SCRIPT_PATH=%GHIDRAMCP_SCRIPT_PATH%"
    echo Using GHIDRAMCP_SCRIPT_PATH from environment: !SCRIPT_PATH!
) else (
    REM Default to user's ghidra_scripts directory
    set "SCRIPT_PATH=%USERPROFILE%\ghidra_scripts"
    echo Using default user script path: !SCRIPT_PATH!
)

REM Validate script exists
set "SCRIPT_FILE=!SCRIPT_PATH!\GhidraMCPHeadlessServer.java"

dir "!SCRIPT_FILE!" >nul 2>&1
if errorlevel 1 (
    echo ERROR: GhidraMCPHeadlessServer.java not found in: !SCRIPT_PATH!
    echo.
    echo Please ensure the script is available or set GHIDRAMCP_SCRIPT_PATH
    exit /b 1
)

echo Script found: !SCRIPT_FILE!

REM Check if we should skip analysis
set "ANALYSIS_FLAG="
if defined GHIDRAMCP_NO_ANALYSIS (
    set "ANALYSIS_FLAG=-noanalysis"
    echo Skipping re-analysis (GHIDRAMCP_NO_ANALYSIS is set)
)

REM Determine process command
set "PROCESS_CMD="
if not "!PROGRAM_NAME!"=="" (
    set "PROCESS_CMD=-process !PROGRAM_NAME!"
    echo Processing specific program: !PROGRAM_NAME!
) else (
    REM If no program name specified, process all programs in project
    echo Processing all programs in project
)

echo.
echo ===========================================
echo GhidraMCP Headless Launcher (Existing Project)
echo ===========================================
echo Ghidra: !GHIDRA_DIR!
echo Project File: !GPR_FILE!
echo Project Location: !PROJECT_LOCATION!
echo Project Name: !PROJECT_NAME!
if not "!PROGRAM_NAME!"=="" echo Program: !PROGRAM_NAME!
echo Port: !GHIDRAMCP_PORT!
echo Keep Running: !GHIDRAMCP_KEEP_RUNNING!
echo Script Path: !SCRIPT_PATH!
if "!ANALYSIS_FLAG!"=="-noanalysis" (
    echo Analysis: SKIP
) else (
    echo Analysis: ENABLED
)
echo ===========================================
echo.

echo Starting Ghidra analyzeHeadless with existing project...
echo.

REM When using an existing project, open it WITHOUT processing
REM Then run the script which will handle getting the program from the project
if not "!PROGRAM_NAME!"=="" (
    REM Open project and run script - DO NOT use -process or -import
    REM The script will need to open the program itself
    "!GHIDRA_DIR!\support\analyzeHeadless.bat" ^
        "!PROJECT_LOCATION!" "!PROJECT_NAME!" ^
        -scriptPath "!SCRIPT_PATH!" ^
        -postScript GhidraMCPHeadlessServer.java "!PROGRAM_NAME!"
) else (
    REM Process first program in project
    "!GHIDRA_DIR!\support\analyzeHeadless.bat" ^
        "!PROJECT_LOCATION!" "!PROJECT_NAME!" ^
        -scriptPath "!SCRIPT_PATH!" ^
        -postScript GhidraMCPHeadlessServer.java
)

exit /b !ERRORLEVEL!

:show_help
echo.
echo GhidraMCP Headless Launcher for Existing Projects
echo.
echo Usage:
echo   %~nx0 ^<project_gpr_file^> [program_name]
echo.
echo Arguments:
echo   project_gpr_file    - Full path to the .gpr project file
echo   program_name        - (Optional) Name of specific program in project to process
echo                         If omitted, processes all programs in project
echo.
echo Environment Variables (Required):
echo   GHIDRA_INSTALL_DIR      - Ghidra installation directory (REQUIRED)
echo.
echo Environment Variables (Optional):
echo   GHIDRAMCP_PORT          - HTTP server port (default: 8192)
echo   GHIDRAMCP_KEEP_RUNNING  - Keep server running (default: true)
echo   GHIDRAMCP_SCRIPT_PATH   - Path to GhidraMCPHeadlessServer.java
echo                             (default: %%USERPROFILE%%\ghidra_scripts)
echo   GHIDRAMCP_NO_ANALYSIS   - If set, skip re-analysis (-noanalysis flag)
echo.
echo Examples:
echo   REM Open project, process all programs
echo   set GHIDRA_INSTALL_DIR=C:\Dev\ghidra_11.4.2_PUBLIC
echo   %~nx0 "C:\Dev\Ghidra\Projects\MyProject\MyProject.gpr"
echo.
echo   REM Open project, process specific program
echo   %~nx0 "C:\Dev\Ghidra\Projects\f9495e968f9a1610_20250826_090532\f9495e968f9a1610_20250826_090532.gpr" "malware.exe"
echo.
echo   REM Skip re-analysis for faster startup
echo   set GHIDRAMCP_NO_ANALYSIS=1
echo   %~nx0 "C:\Dev\Ghidra\Projects\MyProject\MyProject.gpr"
echo.
echo   REM Use different port
echo   set GHIDRAMCP_PORT=9000
echo   %~nx0 "C:\Dev\Ghidra\Projects\MyProject\MyProject.gpr"
echo.
echo Note: The project must already exist and contain analyzed programs.
echo       Use launch_headless.bat to import and analyze new files.
echo.
exit /b 1
