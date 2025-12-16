# GhidraMCP Headless Server - Feature Parity Implementation Plan

**Date Created**: 2025-01-11  
**Status**: COMPREHENSIVE ANALYSIS COMPLETE  
**Priority**: CRITICAL - Production Blocker  

---

## Executive Summary

The current `GhidraMCPHeadlessServer.java` script does NOT have feature parity with the production GUI MCP plugin. This document provides a **COMPREHENSIVE** plan to achieve complete feature parity by:

1. Adopting the **PluginState abstraction** architecture used by the GUI plugin
2. Using the **exact same endpoint classes** as the GUI plugin
3. Ensuring **IDENTICAL API responses** (HATEOAS format with ResponseBuilder)
4. Implementing **ALL missing endpoints** from the GUI version

---

## Current State Analysis

### Architecture Comparison

| Component | GUI Plugin | Current Headless Server | Status |
|-----------|-----------|------------------------|--------|
| **Base Class** | `Plugin` | `GhidraScript` | ✅ Appropriate |
| **Abstraction Layer** | `GUIPluginState` implements `PluginState` | Manual implementations | ❌ NOT USING |
| **Endpoint Architecture** | 16+ separate endpoint classes in `endpoints/` package | Inline handler methods | ❌ COMPLETELY DIFFERENT |
| **Response Format** | `ResponseBuilder` with HATEOAS | Manual JSON construction | ❌ INCONSISTENT |
| **Decompiler Management** | Managed by `PluginState` | Direct `DecompInterface` | ⚠️ WORKS BUT NOT REUSABLE |
| **Error Handling** | Standardized via `AbstractEndpoint` | Custom error methods | ❌ INCONSISTENT |

### Missing Components in Headless Server

#### 1. PluginState Abstraction ❌
- **NOT USING** the `HeadlessPluginState` wrapper
- Accessing Ghidra APIs directly instead of through abstraction
- Cannot share endpoint code with GUI plugin

#### 2. Endpoint Classes ❌
The headless server uses **INLINE HANDLERS** instead of the production endpoint classes:

**MISSING ENDPOINT CLASSES (16 total):**
```
✗ AnalysisEndpoints.java
✗ ClassEndpoints.java  
✗ DataEndpoints.java
✗ DataTypeEndpoints.java
✗ EquateEndpoints.java
✗ FunctionEndpoints.java
✗ InstanceEndpoints.java
✗ MemoryEndpoints.java
✗ NamespaceEndpoints.java
✗ PcodeEndpoints.java (empty but registered)
✗ ProgramEndpoints.java
✗ SegmentEndpoints.java
✗ SymbolEndpoints.java
✗ VariableEndpoints.java
✗ XrefsEndpoints.java
```

#### 3. ResponseBuilder ❌
- NOT using `au.federation.ghidra.api.ResponseBuilder`
- Manual JSON construction with basic Maps
- Missing HATEOAS `_links` structure
- Missing `instance` and `id` fields
- Inconsistent response format

#### 4. Missing Endpoints

**Meta Endpoints:**
- ✗ `/` - Root endpoint with HATEOAS discovery
- ✓ `/info` - EXISTS but wrong format
- ✓ `/plugin-version` - EXISTS but wrong format
- ✗ `/projects` - NOT IMPLEMENTED
- ✗ `/instances` - NOT IMPLEMENTED (requires InstanceEndpoints)
- ✗ `/registerInstance` - NOT IMPLEMENTED
- ✗ `/unregisterInstance` - NOT IMPLEMENTED

**Program Endpoints:**
- ✗ `/program` - NOT IMPLEMENTED (only basic /info)
- ✗ `/address` - Current address (GUI only feature)
- ✗ `/function` - Current function (GUI only feature)

**Function Endpoints:**
- ✓ `/functions` - EXISTS but simplified
- ✓ `/functions/{address}` - EXISTS  
- ✗ `/functions/by-name/{name}` - NOT IMPLEMENTED
- ✓ `/functions/{address}/decompile` - EXISTS
- ✓ `/functions/{address}/calls` - EXISTS
- ✓ `/functions/{address}/callers` - EXISTS
- ✓ `/functions/{address}/variables` - EXISTS
- ✓ `/functions/{address}/parameters` - EXISTS
- ✗ `/functions/{address}/disassembly` - NOT IMPLEMENTED
- ✗ `/functions/{address}/signature` - NOT IMPLEMENTED
- ✗ `/functions/{address}/stack` - NOT IMPLEMENTED
- ✗ `/functions/{address}/pcode` - NOT IMPLEMENTED
- ✗ `/functions/thunks` - Partial (exists but different format)
- ✗ `/functions/external` - Partial (exists but different format)

**Analysis Endpoints:**
- ✗ `/analysis` - NOT USING AnalysisEndpoints class
- ✗ `/analysis/callgraph` - NOT IMPLEMENTED

**Symbol Endpoints:**
- ✗ `/symbols` - Simplified version only
- ✗ `/symbols/imports` - NOT IMPLEMENTED
- ✗ `/symbols/exports` - NOT IMPLEMENTED

**Data Endpoints:**
- ✗ `/data` - NOT USING DataEndpoints class
- ✗ `/data/delete` - NOT IMPLEMENTED
- ✗ `/data/update` - NOT IMPLEMENTED
- ✗ `/data/type` - NOT IMPLEMENTED
- ✗ `/strings` - Simplified version (should be in DataEndpoints)

**Memory Endpoints:**
- ✗ `/memory` - Simplified version
- ✗ `/memory/{address}` - NOT IMPLEMENTED with proper sub-resources

**DataType Endpoints:**
- ✗ `/datatypes` - Simplified version
- ✗ `/datatypes/enums` - NOT IMPLEMENTED
- ✗ `/datatypes/enums/{path}` - NOT IMPLEMENTED

**Equate Endpoints:**
- ✗ `/equates` - Simplified version
- ✗ `/equates/{name}` - NOT IMPLEMENTED
- ✗ `/equates/assign` - NOT IMPLEMENTED
- ✗ `/equates/at/{address}` - NOT IMPLEMENTED
- ✗ `/equates/value/{value}` - NOT IMPLEMENTED

**Segment Endpoints:**
- ✗ `/segments` - Simplified version (NOT using SegmentEndpoints class)

**Namespace Endpoints:**
- ✗ `/namespaces` - Simplified version

**Variable Endpoints:**
- ✗ `/variables` - NOT USING VariableEndpoints class

**Xref Endpoints:**
- ✗ `/xrefs` - Simplified version

**Class Endpoints:**
- ✗ `/classes` - Simplified version

**Comment Endpoints:**
- ✗ `/comments/*` - NOT USING proper endpoint structure

**Pcode Endpoints:**
- ✗ ALL `/pcode/*` endpoints - NOT IMPLEMENTED (PcodeEndpoints.java is empty)

---

## COMPREHENSIVE Implementation Plan

### Phase 1: Adopt PluginState Architecture ⭐ CRITICAL

**Objective**: Replace direct Ghidra API access with `HeadlessPluginState`

**Files to Modify:**
1. `GhidraMCPHeadlessServer.java`

**Changes Required:**

```java
// BEFORE (current - line ~36-40)
public class GhidraMCPHeadlessServer extends GhidraScript {
    private static HttpServer server;
    private Program program;
    private DecompInterface decompiler;
    private int port = 8192;

// AFTER (target)
public class GhidraMCPHeadlessServer extends GhidraScript {
    private static HttpServer server;
    private HeadlessPluginState pluginState;
    private int port = 8192;
```

**Implementation Steps:**

1. **Import HeadlessPluginState**
   ```java
   import au.federation.ghidra.HeadlessPluginState;
   import au.federation.ghidra.PluginState;
   ```

2. **Initialize PluginState in run() method**
   ```java
   @Override
   public void run() throws Exception {
       // Get port from environment
       String portEnv = System.getenv("GHIDRAMCP_PORT");
       if (portEnv != null) {
           port = Integer.parseInt(portEnv);
       }
       
       // Create PluginState wrapper
       pluginState = new HeadlessPluginState(this, port);
       
       Program program = getCurrentProgram();
       if (program == null) {
           println("ERROR: No program is currently open!");
           return;
       }
       
       println("Program: " + program.getName());
       println("Port: " + port);
       
       // ... rest of initialization
   }
   ```

3. **Remove direct decompiler management**
   - Delete `private DecompInterface decompiler;`
   - Remove `decompiler.openProgram(program);`
   - Remove `decompiler.dispose();`
   - Let endpoint classes use `pluginState.createDecompiler()`

4. **Replace all `program` references with `pluginState.getCurrentProgram()`**

**Estimated Effort**: 2 hours  
**Risk**: LOW - Well-tested abstraction exists

---

### Phase 2: Replace Inline Handlers with Endpoint Classes ⭐⭐⭐ CRITICAL

**Objective**: Remove ALL inline handler methods and use production endpoint classes

**Current Problem:**
The headless server has ~1900 lines of inline handler methods that duplicate the logic in the endpoint classes. This causes:
- Response format inconsistencies
- Missing features
- Code duplication
- Maintenance nightmare

**Solution:**
Use the EXACT SAME endpoint classes as the GUI plugin.

**Files to Modify:**
1. `GhidraMCPHeadlessServer.java` - DELETE ~1500 lines of inline handlers

**Changes Required:**

#### Step 1: Delete ALL inline register methods (~1500 lines)

**DELETE THESE METHODS ENTIRELY:**
```java
private void registerFunctionEndpoints()      // Lines ~179-526
private void registerStringEndpoints()        // Lines ~527-584
private void registerSymbolEndpoints()        // Lines ~585-639
private void registerMemoryEndpoints()        // Lines ~640-865
private void registerXrefEndpoints()          // Lines ~866-921
private void registerDataEndpoints()          // Lines ~922-1069
private void registerDataTypeEndpoints()      // Lines ~1070-1196
private void registerEquateEndpoints()        // Lines ~1197-1226
private void registerNamespaceEndpoints()     // Lines ~1227-1278
private void registerProgramEndpoints()       // Lines ~1279-1436
private void registerSectionEndpoints()       // Lines ~1437-1550
private void registerSegmentEndpoints()       // Lines ~1551-1583
private void registerVariableEndpoints()      // Lines ~1584-1625
private void registerCommentsEndpoints()      // Lines ~1626-1661
private void registerAnalysisEndpoints()      // Lines ~1662-1716
private void registerClassEndpoints()         // Lines ~1717-end
```

**DELETE THESE HELPER METHODS:**
```java
private void handleListFunctions()
private void handleGetFunction()
private void handleDecompileFunction()
private void handleFunctionCalls()
private void handleFunctionCallers()
private void handleFunctionVariables()
private void handleFunctionParameters()
private void handleThunkFunctions()
private void handleExternalFunctions()
// ... ALL handler methods (50+ methods to delete)
```

#### Step 2: Import production endpoint classes

```java
// Add these imports at top of file
import au.federation.ghidra.endpoints.*;
import au.federation.ghidra.api.ResponseBuilder;
import au.federation.ghidra.util.HttpUtil;
```

#### Step 3: Replace run() method endpoint registration

**DELETE THIS (lines ~74-97):**
```java
registerSystemEndpoints();
registerAnalysisEndpoints();
registerClassEndpoints();
registerDataEndpoints();
registerDataTypeEndpoints();
registerEquateEndpoints();
registerFunctionEndpoints();
registerMemoryEndpoints();
registerNamespaceEndpoints();
registerProgramEndpoints();
registerSectionEndpoints();
registerSegmentEndpoints();
registerStringEndpoints();
registerSymbolEndpoints();
registerVariableEndpoints();
registerXrefEndpoints();
registerCommentsEndpoints();
```

**REPLACE WITH THIS:**
```java
// Register meta endpoints (/, /info, /plugin-version)
registerMetaEndpoints(server);

// Register instance endpoints
new InstanceEndpoints(pluginState).registerEndpoints(server);

// Register ALL program-dependent endpoints using production classes
new FunctionEndpoints(pluginState).registerEndpoints(server);
new VariableEndpoints(pluginState).registerEndpoints(server);
new ClassEndpoints(pluginState).registerEndpoints(server);
new SegmentEndpoints(pluginState).registerEndpoints(server);
new SymbolEndpoints(pluginState).registerEndpoints(server);
new NamespaceEndpoints(pluginState).registerEndpoints(server);
new DataEndpoints(pluginState).registerEndpoints(server);
new MemoryEndpoints(pluginState).registerEndpoints(server);
new XrefsEndpoints(pluginState).registerEndpoints(server);
new AnalysisEndpoints(pluginState).registerEndpoints(server);
new ProgramEndpoints(pluginState).registerEndpoints(server);
new DataTypeEndpoints(pluginState).registerEndpoints(server);
new EquateEndpoints(pluginState).registerEndpoints(server);

// Register root endpoint last
registerRootEndpoint(server);
```

#### Step 4: Keep only meta endpoint registration methods

**KEEP ONLY THESE 3 METHODS (update to use ResponseBuilder):**

```java
private void registerMetaEndpoints(HttpServer server) {
    // /plugin-version endpoint
    server.createContext("/plugin-version", exchange -> {
        try {
            if ("GET".equals(exchange.getRequestMethod())) {
                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(Map.of(
                        "plugin_version", ApiConstants.PLUGIN_VERSION,
                        "api_version", ApiConstants.API_VERSION,
                        "mode", "headless"
                    ))
                    .addLink("self", "/plugin-version")
                    .addLink("root", "/");
                    
                HttpUtil.sendJsonResponse(exchange, builder.build(), 200, port);
            } else {
                HttpUtil.sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED", port);
            }
        } catch (IOException e) {
            pluginState.printerr("Error handling /plugin-version", e);
        }
    });
    
    // /info endpoint
    server.createContext("/info", exchange -> {
        try {
            Map<String, Object> infoData = new HashMap<>();
            infoData.put("mode", "headless");
            
            Program program = pluginState.getCurrentProgram();
            if (program != null) {
                infoData.put("file", program.getName());
                infoData.put("architecture", program.getLanguage().getLanguageID().getIdAsString());
                infoData.put("processor", program.getLanguage().getProcessor().toString());
                infoData.put("addressSize", program.getAddressFactory().getDefaultAddressSpace().getSize());
                infoData.put("executable", program.getExecutablePath());
            }
            
            infoData.put("serverPort", port);
            infoData.put("serverStartTime", System.currentTimeMillis());
            
            ResponseBuilder builder = new ResponseBuilder(exchange, port)
               .success(true)
               .result(infoData)
               .addLink("self", "/info")
               .addLink("root", "/")
               .addLink("instances", "/instances");
            
            if (program != null) {
                builder.addLink("program", "/program");
            }
            
            HttpUtil.sendJsonResponse(exchange, builder.build(), 200, port);
        } catch (Exception e) {
            pluginState.printerr("Error serving /info endpoint", e);
            HttpUtil.sendErrorResponse(exchange, 500, "Internal server error", "INTERNAL_ERROR", port);
        }
    });
}

private void registerRootEndpoint(HttpServer server) {
    server.createContext("/", exchange -> {
        try {
            if (!exchange.getRequestURI().getPath().equals("/")) {
                HttpUtil.sendErrorResponse(exchange, 404, "Endpoint not found", "ENDPOINT_NOT_FOUND", port);
                return;
            }
        
            Map<String, Object> rootData = new HashMap<>();
            rootData.put("message", "GhidraMCP API " + ApiConstants.API_VERSION);
            rootData.put("documentation", "See GHIDRA_HTTP_API.md for full API documentation");
            rootData.put("mode", "headless");
            
            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                .success(true)
                .result(rootData)
                .addLink("self", "/")
                .addLink("info", "/info")
                .addLink("plugin-version", "/plugin-version")
                .addLink("instances", "/instances");
            
            // Add program-dependent links if program is loaded
            if (pluginState.getCurrentProgram() != null) {
                builder.addLink("program", "/program")
                       .addLink("functions", "/functions")
                       .addLink("symbols", "/symbols")
                       .addLink("data", "/data")
                       .addLink("strings", "/strings")
                       .addLink("segments", "/segments")
                       .addLink("memory", "/memory")
                       .addLink("xrefs", "/xrefs")
                       .addLink("analysis", "/analysis")
                       .addLink("datatypes", "/datatypes")
                       .addLink("equates", "/equates")
                       .addLink("classes", "/classes")
                       .addLink("namespaces", "/namespaces")
                       .addLink("variables", "/variables");
            }
            
            HttpUtil.sendJsonResponse(exchange, builder.build(), 200, port);
        } catch (Exception e) {
            pluginState.printerr("Error serving / endpoint", e);
            HttpUtil.sendErrorResponse(exchange, 500, "Internal server error", "INTERNAL_ERROR", port);
        }
    });
}
```

**Estimated Effort**: 6 hours  
**Risk**: MEDIUM - Large refactor but straightforward replacement  
**Lines Deleted**: ~1500 lines  
**Lines Added**: ~100 lines

---

### Phase 3: Add Missing ApiConstants ⭐

**Objective**: Ensure all constants used by endpoint classes are available

**Files to Modify:**
1. `GhidraMCPHeadlessServer.java`

**Add Import:**
```java
import au.federation.ghidra.api.ApiConstants;
```

**Verify ApiConstants.java contains:**
```java
public static final String PLUGIN_VERSION = "v2.0.0.1";
public static final int API_VERSION = 2510;
public static final int DEFAULT_PORT = 8192;
public static final int MAX_PORT_ATTEMPTS = 10;
```

**Estimated Effort**: 30 minutes  
**Risk**: LOW

---

### Phase 4: Add Instance Management ⭐⭐

**Objective**: Enable headless instances to register with InstanceEndpoints

**Files to Modify:**
1. `GhidraMCPHeadlessServer.java`

**Add Static Instance Map:**
```java
public class GhidraMCPHeadlessServer extends GhidraScript {
    // Made public static to be accessible by InstanceEndpoints
    public static final Map<Integer, Object> activeInstances = new ConcurrentHashMap<>();
    
    private static HttpServer server;
    private HeadlessPluginState pluginState;
    private int port = 8192;
```

**Register Instance on Startup:**
```java
@Override
public void run() throws Exception {
    // ... port determination ...
    
    // Create PluginState wrapper
    pluginState = new HeadlessPluginState(this, port);
    
    // Register this instance
    activeInstances.put(port, this);
    
    // ... rest of initialization ...
}
```

**Unregister on Shutdown:**
```java
// In finally block
finally {
    if (decompiler != null) {
        decompiler.dispose();
    }
    if (server != null) {
        server.stop(0);
        println("Server stopped.");
    }
    // Unregister instance
    activeInstances.remove(port);
}
```

**Update InstanceEndpoints.java** to check both maps:
```java
// In handleInstances() method
Map<Integer, Object> allInstances = new HashMap<>();
allInstances.putAll(GhidraMCPPlugin.activeInstances);
allInstances.putAll(GhidraMCPHeadlessServer.activeInstances); // Add this line
```

**Estimated Effort**: 1 hour  
**Risk**: LOW

---

### Phase 5: Remove Utility Methods ⭐

**Objective**: Delete duplicate JSON/HTTP utility methods

**Files to Modify:**
1. `GhidraMCPHeadlessServer.java`

**DELETE THESE METHODS (~200 lines):**
```java
private void sendJsonResponse()
private void sendError()
private void logRequest()
private void safeHandle()
private String toJson()
private String mapToJson()
private String listToJson()
private String escapeJson()
private Map<String, String> parseQuery()
private Address parseAddressString()
// ... all utility methods
```

**REPLACE WITH IMPORTS:**
```java
import au.federation.ghidra.util.HttpUtil;
import au.federation.ghidra.util.GhidraUtil;
```

**Use HttpUtil methods:**
- `HttpUtil.sendJsonResponse()`
- `HttpUtil.sendErrorResponse()`
- `HttpUtil.handleOptionsRequest()`

**Use GhidraUtil methods:**
- `GhidraUtil.parseAddress()`
- etc.

**Estimated Effort**: 2 hours  
**Risk**: LOW

---

### Phase 6: Update Instance Detection ⭐

**Objective**: Make InstanceEndpoints properly detect headless instances

**Files to Modify:**
1. `src/main/java/au/federation/ghidra/endpoints/InstanceEndpoints.java`

**Update helper methods:**
```java
private boolean isBaseInstance(Object instance) {
    if (instance instanceof GhidraMCPPlugin) {
        return ((GhidraMCPPlugin) instance).isBaseInstance();
    } else if (instance instanceof GhidraMCPHeadlessServer) {
        // Check if on default port
        // TODO: Add isBaseInstance() method to headless server
        return false;
    }
    return false;
}

private Program getProgramFromInstance(Object instance) {
    if (instance instanceof GhidraMCPPlugin) {
        return ((GhidraMCPPlugin) instance).getCurrentProgram();
    } else if (instance instanceof GhidraMCPHeadlessServer) {
        return ((GhidraMCPHeadlessServer) instance).getCurrentProgram();
    }
    return null;
}
```

**Add to GhidraMCPHeadlessServer:**
```java
public Program getCurrentProgram() {
    return pluginState.getCurrentProgram();
}

public boolean isBaseInstance() {
    return port == ApiConstants.DEFAULT_PORT;
}
```

**Estimated Effort**: 1 hour  
**Risk**: LOW

---

### Phase 7: Testing & Validation ⭐⭐⭐

**Objective**: Ensure headless server produces IDENTICAL responses to GUI plugin

**Test Plan:**

#### 1. Response Format Tests
For EACH endpoint, verify:
- ✓ `success` field present
- ✓ `id` field present (UUID or request ID)
- ✓ `instance` field present (`http://localhost:{port}`)
- ✓ `_links` object present with HATEOAS links
- ✓ `result` field contains data
- ✓ Response structure IDENTICAL to GUI version

**Test Script:**
```python
import requests
import json

GUI_PORT = 8192
HEADLESS_PORT = 8193

def compare_response_structure(endpoint):
    gui_resp = requests.get(f"http://localhost:{GUI_PORT}{endpoint}").json()
    headless_resp = requests.get(f"http://localhost:{HEADLESS_PORT}{endpoint}").json()
    
    # Compare keys
    assert set(gui_resp.keys()) == set(headless_resp.keys()), \
        f"Key mismatch: GUI={gui_resp.keys()}, Headless={headless_resp.keys()}"
    
    # Compare _links structure
    assert set(gui_resp.get('_links', {}).keys()) == set(headless_resp.get('_links', {}).keys()), \
        f"Links mismatch"
    
    print(f"✓ {endpoint} - Response structure matches")

# Test all endpoints
endpoints = [
    "/",
    "/info",
    "/plugin-version",
    "/instances",
    "/program",
    "/functions",
    "/functions/by-name/main",
    "/symbols",
    "/symbols/imports",
    "/symbols/exports",
    "/data",
    "/strings",
    "/memory",
    "/xrefs",
    "/analysis",
    "/analysis/callgraph",
    "/datatypes",
    "/equates",
    "/segments",
    "/namespaces",
    "/variables",
    "/classes",
]

for ep in endpoints:
    compare_response_structure(ep)
```

#### 2. Endpoint Coverage Tests
Verify ALL endpoints from GUI are available in headless:

**Automated Test:**
```python
def test_endpoint_coverage():
    gui_root = requests.get(f"http://localhost:{GUI_PORT}/").json()
    headless_root = requests.get(f"http://localhost:{HEADLESS_PORT}/").json()
    
    gui_links = set(gui_root['_links'].keys())
    headless_links = set(headless_root['_links'].keys())
    
    missing = gui_links - headless_links
    assert len(missing) == 0, f"Missing endpoints in headless: {missing}"
```

#### 3. Data Consistency Tests
For each endpoint, verify data contents match:

```python
def test_data_consistency():
    # Load same binary in both
    # Compare function counts
    gui_funcs = requests.get(f"http://localhost:{GUI_PORT}/functions").json()
    headless_funcs = requests.get(f"http://localhost:{HEADLESS_PORT}/functions").json()
    
    assert gui_funcs['result']['count'] == headless_funcs['result']['count'], \
        "Function count mismatch"
```

**Estimated Effort**: 8 hours  
**Risk**: HIGH - May reveal additional issues

---

## Implementation Order

**CRITICAL PATH:**

1. **Phase 1** (2 hrs) → Adopt PluginState architecture
2. **Phase 2** (6 hrs) → Replace inline handlers with endpoint classes  
   ⚠️ **BLOCKER** - Everything depends on this
3. **Phase 3** (0.5 hrs) → Add ApiConstants import
4. **Phase 4** (1 hr) → Instance management
5. **Phase 5** (2 hrs) → Remove utility methods
6. **Phase 6** (1 hr) → Update instance detection
7. **Phase 7** (8 hrs) → Testing & validation

**Total Estimated Effort**: 20.5 hours (~3 days)

---

## Expected Outcomes

### Before (Current State)

```java
// GhidraMCPHeadlessServer.java - 2037 lines
// - 1500 lines of duplicate handler code
// - Manual JSON construction
// - No HATEOAS support
// - Missing 50+ endpoints
// - Inconsistent responses
```

### After (Target State)

```java
// GhidraMCPHeadlessServer.java - ~450 lines
// - Uses production endpoint classes (0 duplicate code)
// - Uses ResponseBuilder (consistent HATEOAS)
// - ALL 80+ endpoints available
// - IDENTICAL responses to GUI plugin
// - Maintainable and extensible
```

### Response Format Comparison

**BEFORE:**
```json
{
  "success": true,
  "result": {
    "functions": [...],
    "total": 1234
  }
}
```

**AFTER:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "instance": "http://localhost:8192",
  "success": true,
  "result": {
    "functions": [...],
    "total": 1234
  },
  "_links": {
    "self": {"href": "/functions?offset=0&limit=50"},
    "next": {"href": "/functions?offset=50&limit=50"},
    "program": {"href": "/program"}
  }
}
```

---

## Risk Assessment

### HIGH RISKS

1. **Breaking Existing Clients** ⚠️
   - Response format will change significantly
   - `_links` and `instance` fields added
   - **Mitigation**: Version the API (v2 endpoints)

2. **Testing Coverage** ⚠️
   - Large refactor with many edge cases
   - **Mitigation**: Comprehensive test suite (Phase 7)

### MEDIUM RISKS

1. **Endpoint Order Registration**
   - HttpServer path matching is prefix-based
   - **Mitigation**: Follow exact order from GhidraMCPPlugin

2. **Performance**
   - Endpoint classes may have different performance characteristics
   - **Mitigation**: Load testing before production

### LOW RISKS

1. **Compilation Errors**
   - Well-tested classes being reused
   - **Mitigation**: Incremental compilation

---

## Success Criteria

✅ **MUST HAVE:**
1. ALL 16 endpoint classes registered and functional
2. Response format IDENTICAL to GUI plugin (with HATEOAS)
3. ALL endpoints from GUI available in headless
4. Zero code duplication between GUI and headless
5. Passing automated test suite (100% endpoint coverage)

✅ **SHOULD HAVE:**
1. Response time < 200ms for simple endpoints
2. Documentation updated
3. Example client code updated

✅ **NICE TO HAVE:**
1. API versioning (v1 vs v2)
2. Backward compatibility layer

---

## Maintenance Impact

**Code Reduction:**
- Delete: ~1500 lines of duplicate code
- Add: ~100 lines of wrapper code
- **Net: -1400 lines (68% reduction)**

**Maintainability:**
- **BEFORE**: Changes to endpoints require updates in 2 places (GUI plugin + headless server)
- **AFTER**: Changes to endpoints require update in 1 place (endpoint class)
- **Impact**: 50% reduction in maintenance effort

**Testing:**
- **BEFORE**: Separate test suites for GUI and headless
- **AFTER**: Single test suite for endpoint classes, minimal mode-specific tests

---

## Conclusion

The current `GhidraMCPHeadlessServer.java` is **NOT production-ready** due to:
1. Missing 50+ endpoints
2. Inconsistent response formats (no HATEOAS)
3. 1500 lines of duplicate code
4. No code sharing with GUI plugin

**RECOMMENDATION**: Implement this plan IMMEDIATELY to achieve feature parity.

**CRITICAL BLOCKER**: Phase 2 (Replace inline handlers) is the most important change. All other improvements depend on this architectural fix.

**ESTIMATED TIMELINE**: 3 days for implementation + testing
