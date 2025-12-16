# GhidraMCP Headless Mode

This document explains how to use GhidraMCP in headless mode, enabling AI-assisted reverse engineering without the Ghidra GUI.

## Overview

GhidraMCP can run in two modes:

1. **GUI Mode** (Plugin): Runs inside Ghidra's GUI as a plugin
2. **Headless Mode** (Script): Runs via Ghidra's `analyzeHeadless` command without GUI

Both modes expose the **identical HATEOAS HTTP API**, ensuring that `ghidra_mcp_server.py` works without modification in either mode.

## Architecture

### Abstraction Layer

GhidraMCP uses a `PluginState` interface to provide a unified API for both modes:

- **GUIPluginState**: Wraps `ProgramPlugin` for GUI mode
- **HeadlessPluginState**: Wraps `GhidraScript` for headless mode

All 16 endpoint classes use this abstraction, so they work identically in both modes:

- AnalysisEndpoints
- ClassEndpoints
- DataEndpoints
- DataTypeEndpoints
- EquateEndpoints
- FunctionEndpoints
- InstanceEndpoints
- MemoryEndpoints
- NamespaceEndpoints
- PcodeEndpoints
- ProgramEndpoints
- SegmentEndpoints
- SymbolEndpoints
- VariableEndpoints
- XrefsEndpoints

### HTTP Server

Both modes start an HTTP server on the same port range (8192-8201) with identical endpoints:

- `/` - Root with HATEOAS links
- `/info` - Instance information
- `/plugin-version` - Version information
- `/instances` - List all running instances
- `/functions` - Function analysis
- `/variables` - Variable analysis
- `/symbols` - Symbol information
- `/memory` - Memory analysis
- And all other endpoints...

## Installation

### Plugin Installation (GUI Mode)

1. Build the project: `mvn clean package`
2. Install the extension in Ghidra:
   - File → Install Extensions
   - Click the green `+` icon
   - Select `target/GhidraMCP-*.zip`
   - Restart Ghidra

### Headless Installation

The headless script (`GhidraMCPHeadlessScript.java`) is included in the same extension ZIP:

1. Install the extension as above (same ZIP file)
2. The script will be available in: `<ghidra_install>/Ghidra/Extensions/GhidraMCP/`

## Usage

### Quick Start

#### Windows

```batch
launch_headless.bat "C:\ghidra_11.2.1" "C:\projects" "MyProject" "target.exe"
```

#### Linux/macOS

```bash
./launch_headless.sh "/opt/ghidra" "/home/user/projects" "MyProject" "target.elf"
```

### Environment Variables

- **GHIDRA_INSTALL_DIR**: Ghidra installation directory (overrides command line argument)
- **GHIDRAMCP_PORT**: HTTP server port (default: 8192)
- **GHIDRAMCP_KEEP_RUNNING**: Keep server running after analysis (default: true)

### Manual Invocation

You can also call `analyzeHeadless` directly:

```bash
# Linux/macOS
export GHIDRAMCP_PORT=8192
export GHIDRAMCP_KEEP_RUNNING=true

$GHIDRA_INSTALL_DIR/support/analyzeHeadless \
    "/path/to/projects" "MyProject" \
    -import "/path/to/binary.elf" \
    -postScript GhidraMCPHeadlessScript.java

# Windows
set GHIDRAMCP_PORT=8192
set GHIDRAMCP_KEEP_RUNNING=true

"%GHIDRA_INSTALL_DIR%\support\analyzeHeadless.bat" ^
    "C:\path\to\projects" "MyProject" ^
    -import "C:\path\to\binary.exe" ^
    -postScript GhidraMCPHeadlessScript.java
```

### Using with Existing Projects

To run on an existing project without importing a new file:

```bash
$GHIDRA_INSTALL_DIR/support/analyzeHeadless \
    "/path/to/projects" "MyProject" \
    -process "existing_file.exe" \
    -postScript GhidraMCPHeadlessScript.java
```

## Configuration

### Port Selection

By default, headless mode tries to use port 8192 (same as GUI mode). If that port is already in use, it will try ports 8193, 8194, etc., up to 8201.

You can specify a different starting port:

```bash
export GHIDRAMCP_PORT=9000  # Try ports 9000-9009
```

### Keep Running

By default, the server keeps running after the script completes, allowing you to interact with it via MCP:

```bash
export GHIDRAMCP_KEEP_RUNNING=true   # Server stays running (default)
export GHIDRAMCP_KEEP_RUNNING=false  # Server stops after script completes
```

When `GHIDRAMCP_KEEP_RUNNING=true`, the server runs indefinitely. Stop it with Ctrl+C.

## Using with ghidra_mcp_server.py

The Python MCP bridge works identically with both GUI and headless modes:

```bash
# Start headless server
./launch_headless.sh "/opt/ghidra" "/projects" "MyProject" "binary.elf"

# In another terminal, start MCP bridge (it will auto-discover the headless instance)
python ghidra_mcp_server.py
```

The MCP bridge will discover headless instances on ports 8192-8201, just like GUI instances.

## Docker Support (Future)

Docker support is planned for easy deployment of headless instances. The Dockerfile will:

1. Install Ghidra
2. Install GhidraMCP extension
3. Import and analyze a binary
4. Start the headless HTTP server
5. Keep running for MCP access

Example (planned):

```bash
docker run -p 8192:8192 -v /path/to/binaries:/binaries ghidramcp:latest /binaries/target.elf
```

## API Differences

The HTTP API is **99% identical** between GUI and headless modes. Minor differences:

### `/info` Endpoint

GUI mode:
```json
{
  "isBaseInstance": true,
  "mode": "gui",
  "project": "MyGhidraProject",
  "projectLocation": "/path/to/project",
  ...
}
```

Headless mode:
```json
{
  "isBaseInstance": true,
  "mode": "headless",
  "project": "headless",
  ...
}
```

### `/plugin-version` Endpoint

Headless mode includes a `mode` field:
```json
{
  "plugin_version": "1.0.0",
  "api_version": "1.0",
  "mode": "headless"
}
```

### `/projects` Endpoint

Headless mode has limited project management:
- Cannot create new projects via API
- Lists current analyzed file as a "project"

## Troubleshooting

### Server Won't Start

**Problem**: HTTP server fails to start

**Solutions**:
1. Check if port is already in use: `netstat -an | grep 8192` (Linux) or `netstat -an | findstr 8192` (Windows)
2. Try a different port: `export GHIDRAMCP_PORT=9000`
3. Check firewall settings

### No Program Loaded

**Problem**: Endpoints return "No program loaded" errors

**Solutions**:
1. Verify you're using `-import` or `-process` with `analyzeHeadless`
2. Check that the binary file exists and is readable
3. Verify Ghidra can analyze the file format

### Script Not Found

**Problem**: `analyzeHeadless` can't find `GhidraMCPHeadlessScript.java`

**Solutions**:
1. Verify the extension is installed in Ghidra
2. Check the script is in: `<ghidra_install>/Ghidra/Extensions/GhidraMCP/ghidra_scripts/`
3. Use `-scriptPath` to point to the correct directory

### Server Stops Immediately

**Problem**: Headless server starts but stops right away

**Solutions**:
1. Ensure `GHIDRAMCP_KEEP_RUNNING=true` is set
2. Check for errors in the Ghidra output
3. Verify Java version compatibility (Java 21+ required)

## Limitations

Current headless mode limitations:

1. **No Project Management**: Limited ability to create/manage Ghidra projects via API
2. **Single Program**: Headless mode works with one program at a time
3. **No GUI Services**: GUI-specific services (like ProgramManager) are not available
4. **Decompiler**: Decompilation works but may be slower than GUI mode

These limitations do **not** affect the core functionality of analyzing binaries and accessing analysis results.

## Performance

Headless mode has several performance advantages:

- **Lower Memory**: No GUI means less memory overhead
- **Faster Startup**: Skips GUI initialization
- **Better for CI/CD**: Can run in automated pipelines
- **Container-Friendly**: Works well in Docker/Kubernetes

Expected memory usage:
- GUI mode: 2-4 GB
- Headless mode: 1-2 GB

## Advanced Usage

### Multiple Instances

You can run multiple headless instances simultaneously:

```bash
# Instance 1 (port 8192)
GHIDRAMCP_PORT=8192 ./launch_headless.sh ... &

# Instance 2 (port 8193)
GHIDRAMCP_PORT=8193 ./launch_headless.sh ... &
```

The `/instances` endpoint will show all running instances (both GUI and headless).

### Scripting

You can script interactions with headless mode:

```bash
# Start headless server
./launch_headless.sh "/opt/ghidra" "/projects" "MyProject" "binary.elf" &

# Wait for server to start
sleep 10

# Query the API
curl http://localhost:8192/info
curl http://localhost:8192/functions

# Stop server
pkill -f GhidraMCPHeadlessScript
```

### Integration with CI/CD

Example GitHub Actions workflow:

```yaml
name: Analyze Binary

on: [push]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Install Ghidra
        run: |
          wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2.1_build/ghidra_11.2.1_PUBLIC_20241105.zip
          unzip ghidra_11.2.1_PUBLIC_20241105.zip
          
      - name: Install GhidraMCP
        run: |
          # Build and install extension
          mvn clean package
          # Install in Ghidra
          
      - name: Analyze Binary
        run: |
          export GHIDRAMCP_KEEP_RUNNING=false
          ./launch_headless.sh ./ghidra_11.2.1_PUBLIC projects MyProject binary.elf
```

## Support

For issues or questions:

1. Check this documentation
2. Review the troubleshooting section
3. Open an issue on GitHub: https://github.com/MartijnvanPraag/GhidraMCP/issues

## Future Enhancements

Planned features for headless mode:

- [ ] Docker images for easy deployment
- [ ] Kubernetes manifests
- [ ] Batch analysis of multiple binaries
- [ ] Enhanced project management API
- [ ] Progress reporting for long-running analysis
- [ ] WebSocket support for real-time updates
- [ ] Persistent sessions across restarts

## Technical Details

### Script Lifecycle

1. **Initialization**: Script starts, reads environment variables
2. **Port Selection**: Finds available port (default 8192)
3. **State Creation**: Creates HeadlessPluginState wrapper
4. **Server Start**: Starts HTTP server with all endpoints
5. **Keep Running**: Enters infinite loop if `GHIDRAMCP_KEEP_RUNNING=true`
6. **Cleanup**: On shutdown, stops server and cleans up resources

### Endpoint Registration

The same endpoint classes are used in both modes:

```java
// Headless mode (GhidraMCPHeadlessScript.java)
new FunctionEndpoints(currentProgram, port, null).registerEndpoints(server);

// GUI mode (GhidraMCPPlugin.java)
new FunctionEndpoints(currentProgram, port, tool).registerEndpoints(server);
```

The `null` tool parameter in headless mode is handled by the abstraction layer.

### Thread Safety

Both GUI and headless modes use:
- `ConcurrentHashMap` for instance tracking
- Cached thread pool for HTTP requests
- Synchronized blocks for critical sections

This ensures thread-safe operation in multi-instance scenarios.

## Comparison: GUI vs Headless

| Feature | GUI Mode | Headless Mode |
|---------|----------|---------------|
| Installation | Ghidra Extension | Same Extension |
| Startup | Manual (Ghidra GUI) | Command Line |
| Memory Usage | 2-4 GB | 1-2 GB |
| HTTP API | Full | Full (identical) |
| MCP Support | Yes | Yes |
| Project Mgmt | Full | Limited |
| Multi-Instance | Yes | Yes |
| Docker | No | Yes (planned) |
| CI/CD | No | Yes |
| Program Switching | GUI-based | Command-line |
| Performance | Normal | Slightly faster |

## Conclusion

GhidraMCP's headless mode provides the same powerful HTTP API as GUI mode, but in a lightweight, automation-friendly package. Whether you're running on a server, in Docker, or in a CI/CD pipeline, headless mode gives you full access to Ghidra's analysis capabilities without the GUI overhead.
