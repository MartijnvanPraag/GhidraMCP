# GhidraMCP Headless Server - Complete Endpoint Documentation

## Overview
The GhidraMCPHeadlessServer.java provides full feature parity with the GUI MCP server, implementing all major endpoint groups for reverse engineering operations in Ghidra's headless mode.

## Implementation Summary

### ✅ Completed Endpoints

#### 1. System Endpoints
- `GET /` - Root endpoint with server info and available endpoints list
- `GET /plugin-version` - Plugin and API version information
- `GET /info` - Program metadata (architecture, processor, etc.)

#### 2. Function Endpoints (`/functions/*`)
- `GET /functions` - List all functions (paginated)
- `GET /functions/{address}` - Get specific function details
- `GET /functions/decompile?address={addr}` - Decompile function
- `GET /functions/calls?address={addr}` - Get functions called by this function
- `GET /functions/callers?address={addr}` - Get functions that call this function
- `GET /functions/variables?address={addr}` - Get local variables
- `GET /functions/parameters?address={addr}` - Get function parameters
- `GET /functions/thunks` - List all thunk functions
- `GET /functions/external` - List all external functions

#### 3. Data Endpoints (`/data/*`)
- `GET /data` - List all defined data (paginated)
- `GET /data/{address}` - Get data at specific address
- `GET /data/references?address={addr}` - Get data cross-references

#### 4. DataType Endpoints (`/datatypes/*`)
- `GET /datatypes` - List all data types
- `GET /datatypes/structs` - List all structures
- `GET /datatypes/enums` - List all enumerations
- `GET /datatypes/categories` - List all categories

#### 5. Equate Endpoints (`/equates/*`)
- `GET /equates` - List all equates with values and reference counts

#### 6. Memory Endpoints (`/memory/*`)
- `GET /memory` - List all memory blocks with permissions
- `GET /memory/read?address={addr}&length={len}` - Read memory bytes
- `GET /memory/search?pattern={hex}` - Search for byte pattern in memory
- `GET /memory/strings?min_length={n}` - Find strings in memory

#### 7. Namespace Endpoints (`/namespaces/*`)
- `GET /namespaces` - List all namespaces with symbol counts

#### 8. Program Endpoints (`/program/*`)
- `GET /program` - Get program information
- `GET /program/imports` - List all imported functions
- `GET /program/exports` - List all exported functions
- `GET /program/entrypoints` - List all entry points

#### 9. Segment Endpoints (`/segments/*`)
- `GET /segments` - List all segments with permissions and properties

#### 10. String Endpoints (`/strings/*`)
- `GET /strings?page={n}&per_page={m}&min_length={l}` - List strings (paginated)

#### 11. Symbol Endpoints (`/symbols/*`)
- `GET /symbols?page={n}&per_page={m}&filter={text}` - List symbols (paginated, filterable)

#### 12. Variable Endpoints (`/variables/*`)
- `GET /variables/global` - List all global variables

#### 13. Cross-Reference Endpoints (`/xrefs/*`)
- `GET /xrefs?address={addr}` - Get references to/from address

#### 14. Comments Endpoints (`/comments/*`)
- `GET /comments?address={addr}` - Get all comment types at address (plate, pre, post, eol, repeatable)

#### 15. Analysis Endpoints (`/analysis/*`)
- `GET /analysis` - Get analysis status

#### 16. Class Endpoints (`/classes/*`)
- `GET /classes` - Stub endpoint (available for future implementation)

## Response Format

All endpoints return JSON with consistent structure:

### Success Response
```json
{
  "success": true,
  "result": {
    // endpoint-specific data
  }
}
```

### Error Response
```json
{
  "success": false,
  "error": "Error message"
}
```

## Pagination

List endpoints support pagination:
- `page` - Page number (default: 1)
- `per_page` - Items per page (default: 50)

Example: `GET /functions?page=2&per_page=100`

## Testing

To test the headless server:

1. Copy `GhidraMCPHeadlessServer.java` to your Ghidra scripts directory
2. Run: `launch_headless.bat <ghidra_dir> <project> <project_name> <binary>`
3. Server starts on port 8192 (or `GHIDRAMCP_PORT` env var)
4. Test endpoints:
   ```bash
   curl http://localhost:8192/
   curl http://localhost:8192/plugin-version
   curl http://localhost:8192/functions?page=1&per_page=10
   curl http://localhost:8192/strings?min_length=5
   ```

## Key Features

### 1. Full Feature Parity
All major endpoints from GUI MCP server are available in headless mode.

### 2. Standalone Script
- No external JAR dependencies
- No package declarations
- Self-contained implementation
- Works with Ghidra's script manager

### 3. Decompiler Integration
Built-in decompiler support for function analysis.

### 4. Memory Operations
- Read memory bytes
- Search for patterns
- Find strings

### 5. Cross-Reference Analysis
Complete reference tracking (to/from) for any address.

### 6. Symbol Management
Full symbol table access with filtering and pagination.

### 7. Program Metadata
- Imports/exports
- Entry points
- Compiler information
- Architecture details

## Usage Examples

### List Functions
```bash
curl "http://localhost:8192/functions?page=1&per_page=50"
```

### Decompile Function
```bash
curl "http://localhost:8192/functions/decompile?address=0x401000"
```

### Get Function Calls
```bash
curl "http://localhost:8192/functions/calls?address=0x401000"
```

### Search Memory
```bash
curl "http://localhost:8192/memory/search?pattern=4883ec28"
```

### Read Memory
```bash
curl "http://localhost:8192/memory/read?address=0x401000&length=64"
```

### Get Cross-References
```bash
curl "http://localhost:8192/xrefs?address=0x401000"
```

### List Strings
```bash
curl "http://localhost:8192/strings?min_length=10&page=1&per_page=20"
```

### Get Comments
```bash
curl "http://localhost:8192/comments?address=0x401000"
```

### Program Imports
```bash
curl "http://localhost:8192/program/imports"
```

## Environment Variables

- `GHIDRAMCP_PORT` - Server port (default: 8192)
- `GHIDRAMCP_KEEP_RUNNING` - Keep server running (default: true)
- `GHIDRAMCP_SCRIPT_PATH` - Custom script location

## File Location

Place `GhidraMCPHeadlessServer.java` in one of:
1. `~/.ghidra/.ghidra_11.x.x_PUBLIC/ghidra_scripts/` (user scripts)
2. `<GHIDRA_DIR>/Ghidra/Features/Base/ghidra_scripts/` (system scripts)
3. Custom location (set `GHIDRAMCP_SCRIPT_PATH`)

## Notes

- All addresses should be in hex format with `0x` prefix
- Pagination limits results to prevent memory issues
- Search operations are capped at 100 results
- Decompiler timeout is set to 30 seconds
- Memory reads are limited to 1KB per request

## Future Enhancements

Potential additions:
- POST/PUT/DELETE operations for data/symbols
- Advanced analysis control
- Class/vtable analysis
- Pcode operations
- Graph generation
- Patch operations
