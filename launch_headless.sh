#!/bin/bash
# GhidraMCP Headless Launcher for Linux/macOS
#
# This script launches GhidraMCP in headless mode using Ghidra's analyzeHeadless.
#
# Usage:
#   launch_headless.sh <ghidra_install_dir> <project_location> <project_name> <file_to_analyze>
#
# Example:
#   ./launch_headless.sh "/opt/ghidra" "/home/user/projects/myproject" "MyProject" "target.elf"
#
# Environment Variables:
#   GHIDRAMCP_PORT - Port for HTTP server (default: 8192)
#   GHIDRAMCP_KEEP_RUNNING - Keep server running after analysis (default: true)
#   GHIDRA_INSTALL_DIR - Ghidra installation directory (overrides first argument)

set -e

# Function to show help
show_help() {
    cat << EOF

GhidraMCP Headless Launcher for Linux/macOS

Usage:
  $0 [ghidra_dir] <project_location> <project_name> <file_to_analyze>

Arguments:
  ghidra_dir        - Ghidra installation directory (optional if GHIDRA_INSTALL_DIR is set)
  project_location  - Directory containing the Ghidra project
  project_name      - Name of the Ghidra project (will be created if doesn't exist)
  file_to_analyze   - Binary file to import and analyze

Environment Variables:
  GHIDRA_INSTALL_DIR      - Ghidra installation directory (overrides ghidra_dir argument)
  GHIDRAMCP_PORT          - HTTP server port (default: 8192)
  GHIDRAMCP_KEEP_RUNNING  - Keep server running after analysis (default: true)

Examples:
  $0 "/opt/ghidra" "/home/user/projects" "MyProject" "target.elf"

  export GHIDRA_INSTALL_DIR="/opt/ghidra"
  export GHIDRAMCP_PORT=9000
  $0 "/home/user/projects" "MyProject" "target.elf"

EOF
    exit 1
}

# Check if help is requested
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    show_help
fi

# Get Ghidra installation directory
if [ -n "$GHIDRA_INSTALL_DIR" ]; then
    GHIDRA_DIR="$GHIDRA_INSTALL_DIR"
    echo "Using GHIDRA_INSTALL_DIR from environment: $GHIDRA_DIR"
elif [ -n "$1" ]; then
    GHIDRA_DIR="$1"
    shift
else
    echo "ERROR: Ghidra installation directory not specified"
    echo ""
    show_help
fi

# Validate Ghidra directory
if [ ! -f "$GHIDRA_DIR/support/analyzeHeadless" ]; then
    echo "ERROR: Invalid Ghidra installation directory: $GHIDRA_DIR"
    echo "Could not find analyzeHeadless script"
    exit 1
fi

echo "Ghidra directory: $GHIDRA_DIR"

# Get remaining arguments
PROJECT_LOCATION="$1"
PROJECT_NAME="$2"
FILE_TO_ANALYZE="$3"

# Validate arguments
if [ -z "$PROJECT_LOCATION" ]; then
    echo "ERROR: Project location not specified"
    show_help
fi

if [ -z "$PROJECT_NAME" ]; then
    echo "ERROR: Project name not specified"
    show_help
fi

if [ -z "$FILE_TO_ANALYZE" ]; then
    echo "ERROR: File to analyze not specified"
    show_help
fi

# Validate file exists
if [ ! -f "$FILE_TO_ANALYZE" ]; then
    echo "ERROR: File not found: $FILE_TO_ANALYZE"
    exit 1
fi

# Set default environment variables if not set
if [ -z "$GHIDRAMCP_PORT" ]; then
    GHIDRAMCP_PORT=8192
    echo "Using default port: $GHIDRAMCP_PORT"
else
    echo "Using GHIDRAMCP_PORT from environment: $GHIDRAMCP_PORT"
fi

if [ -z "$GHIDRAMCP_KEEP_RUNNING" ]; then
    GHIDRAMCP_KEEP_RUNNING=true
fi

# Export environment variables for the script
export GHIDRAMCP_PORT
export GHIDRAMCP_KEEP_RUNNING

# Get the directory where this script is located (where GhidraMCP extension should be)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "==========================================="
echo "GhidraMCP Headless Launcher"
echo "==========================================="
echo "Ghidra: $GHIDRA_DIR"
echo "Project: $PROJECT_LOCATION/$PROJECT_NAME"
echo "File: $FILE_TO_ANALYZE"
echo "Port: $GHIDRAMCP_PORT"
echo "Keep Running: $GHIDRAMCP_KEEP_RUNNING"
echo "Script Dir: $SCRIPT_DIR"
echo "==========================================="
echo ""

# Launch Ghidra in headless mode
# Note: The GhidraMCPHeadlessScript.java should be in the extension's scripts directory
# or you can specify -scriptPath to point to it

echo "Starting Ghidra analyzeHeadless..."
echo ""

"$GHIDRA_DIR/support/analyzeHeadless" \
    "$PROJECT_LOCATION" "$PROJECT_NAME" \
    -import "$FILE_TO_ANALYZE" \
    -scriptPath "$SCRIPT_DIR" \
    -postScript GhidraMCPHeadlessScript.java

exit $?
