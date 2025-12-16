# Quick-Start Implementation Guide
## Achieving Feature Parity in GhidraMCP Headless Server

**Target Audience**: Developers implementing the feature parity plan  
**Time Required**: 3 days  
**Difficulty**: Medium

---

## Prerequisites

✅ **Knowledge Required:**
- Java programming
- Ghidra API basics
- HTTP server concepts
- REST/HATEOAS principles

✅ **Files You'll Modify:**
- `GhidraMCPHeadlessServer.java` (major refactor)
- `InstanceEndpoints.java` (minor update)

✅ **Files You'll Use (No Changes):**
- All 16 endpoint classes in `src/main/java/au/federation/ghidra/endpoints/`
- `HeadlessPluginState.java`
- `ResponseBuilder.java`
- `HttpUtil.java`

---

## Step-by-Step Implementation

### STEP 1: Backup Current Code (5 minutes)

```powershell
# Create backup
Copy-Item GhidraMCPHeadlessServer.java GhidraMCPHeadlessServer.java.backup

# Create git branch
git checkout -b feature/headless-parity
git add .
git commit -m "Backup before headless refactor"
```

---

### STEP 2: Add Imports (10 minutes)

**Location**: Top of `GhidraMCPHeadlessServer.java`

**ADD THESE IMPORTS:**
```java
import au.federation.ghidra.PluginState;
import au.federation.ghidra.HeadlessPluginState;
import au.federation.ghidra.api.ApiConstants;
import au.federation.ghidra.api.ResponseBuilder;
import au.federation.ghidra.util.HttpUtil;
import au.federation.ghidra.util.GhidraUtil;

// Import ALL endpoint classes
import au.federation.ghidra.endpoints.*;

import java.util.concurrent.ConcurrentHashMap;
```

**REMOVE THESE IMPORTS (no longer needed):**
```java
// Delete manual JSON imports if any
```

---

### STEP 3: Update Class Fields (15 minutes)

**Location**: `GhidraMCPHeadlessServer.java` lines 36-42

**BEFORE:**
```java
public class GhidraMCPHeadlessServer extends GhidraScript {
    private static HttpServer server;
    private Program program;
    private DecompInterface decompiler;
    private int port = 8192;
```

**AFTER:**
```java
public class GhidraMCPHeadlessServer extends GhidraScript {
    // Made public static to be accessible by InstanceEndpoints
    public static final Map<Integer, Object> activeInstances = new ConcurrentHashMap<>();
    
    private static HttpServer server;
    private HeadlessPluginState pluginState;
    private int port = 8192;
```

---

### STEP 4: Update run() Method (30 minutes)

**Location**: `GhidraMCPHeadlessServer.java` run() method

**FIND THIS SECTION (lines ~44-75):**
```java
@Override
public void run() throws Exception {
    // Get port from environment variable if set
    String portEnv = System.getenv("GHIDRAMCP_PORT");
    if (portEnv != null) {
        try {
            port = Integer.parseInt(portEnv);
            println("Using port from GHIDRAMCP_PORT: " + port);
        } catch (NumberFormatException e) {
            println("Invalid GHIDRAMCP_PORT, using default: 8192");
        }
    }
    
    program = getCurrentProgram();
    if (program == null) {
        println("ERROR: No program is currently open!");
        return;
    }
    
    // Initialize decompiler
    decompiler = new DecompInterface();
    decompiler.openProgram(program);
```

**REPLACE WITH:**
```java
@Override
public void run() throws Exception {
    // Get port from environment variable if set
    String portEnv = System.getenv("GHIDRAMCP_PORT");
    if (portEnv != null) {
        try {
            port = Integer.parseInt(portEnv);
            println("Using port from GHIDRAMCP_PORT: " + port);
        } catch (NumberFormatException e) {
            println("Invalid GHIDRAMCP_PORT, using default: 8192");
        }
    }
    
    Program program = getCurrentProgram();
    if (program == null) {
        println("ERROR: No program is currently open!");
        return;
    }
    
    // Create PluginState wrapper - THIS IS KEY!
    pluginState = new HeadlessPluginState(this, port);
    
    // Register this instance for multi-instance support
    activeInstances.put(port, this);
```

**FIND THIS SECTION (lines ~74-97):**
```java
    try {
        // Create HTTP server
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.setExecutor(Executors.newCachedThreadPool());
        
        // Register ALL endpoint groups to match GUI server
        registerSystemEndpoints();      // /, /plugin-version, /info
        registerAnalysisEndpoints();     // /analysis/*
        registerClassEndpoints();        // /classes/*
        registerDataEndpoints();         // /data/*
        registerDataTypeEndpoints();     // /datatypes/*
        registerEquateEndpoints();       // /equates/*
        registerFunctionEndpoints();     // /functions/*
        registerMemoryEndpoints();       // /memory/*
        registerNamespaceEndpoints();    // /namespaces/*
        registerProgramEndpoints();      // /program/*
        registerSectionEndpoints();      // /sections/* - CRITICAL for network_config_discover
        registerSegmentEndpoints();      // /segments/*
        registerStringEndpoints();       // /strings/*
        registerSymbolEndpoints();       // /symbols/*
        registerVariableEndpoints();     // /variables/*
        registerXrefEndpoints();         // /xrefs/*
        registerCommentsEndpoints();     // /comments/*
        
        // Start the server
        server.start();
        println("Complete MCP server started on port " + port);
        println("All endpoints are available!");
```

**REPLACE WITH:**
```java
    try {
        // Create HTTP server
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.setExecutor(Executors.newCachedThreadPool());
        
        println("===========================================");
        println("GhidraMCP Headless Server - Feature Parity Version");
        println("===========================================");
        println("Program: " + program.getName());
        println("Port: " + port);
        println("===========================================");
        
        // Register meta endpoints (/, /info, /plugin-version)
        registerMetaEndpoints(server);
        
        // Register instance management endpoints
        new InstanceEndpoints(pluginState).registerEndpoints(server);
        
        // Register ALL program-dependent endpoints using production classes
        // NOTE: Order matters! Most specific paths first
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
        
        // Register root endpoint LAST (catches unmatched paths)
        registerRootEndpoint(server);
        
        // Start the server
        server.start();
        println("Server started successfully!");
        println("All " + (16 + 3 + 1) + " endpoint groups registered");
        println("Access at: http://localhost:" + port);
```

**FIND THE FINALLY BLOCK:**
```java
    } finally {
        if (decompiler != null) {
            decompiler.dispose();
        }
        if (server != null) {
            server.stop(0);
            println("Server stopped.");
        }
    }
```

**REPLACE WITH:**
```java
    } finally {
        if (server != null) {
            server.stop(0);
            println("Server stopped.");
        }
        // Unregister instance
        activeInstances.remove(port);
        
        // Dispose PluginState (handles decompiler cleanup)
        if (pluginState != null) {
            pluginState.dispose();
        }
    }
```

---

### STEP 5: Delete ALL Inline Handler Methods (60 minutes)

**⚠️ CRITICAL: This is the biggest change!**

**DELETE THESE ENTIRE METHODS (lines ~179-1800):**

```java
// DELETE: registerFunctionEndpoints() and ALL its handlers
private void registerFunctionEndpoints() { ... }
private void handleListFunctions() { ... }
private void handleGetFunction() { ... }
private void handleDecompileFunction() { ... }
private void handleFunctionCalls() { ... }
private void handleFunctionCallers() { ... }
private void handleFunctionVariables() { ... }
private void handleFunctionParameters() { ... }
private void handleThunkFunctions() { ... }
private void handleExternalFunctions() { ... }

// DELETE: registerStringEndpoints() and handlers
private void registerStringEndpoints() { ... }

// DELETE: registerSymbolEndpoints() and handlers
private void registerSymbolEndpoints() { ... }

// DELETE: registerMemoryEndpoints() and handlers
private void registerMemoryEndpoints() { ... }

// DELETE: registerXrefEndpoints() and handlers
private void registerXrefEndpoints() { ... }

// DELETE: registerDataEndpoints() and handlers
private void registerDataEndpoints() { ... }

// DELETE: registerDataTypeEndpoints() and handlers
private void registerDataTypeEndpoints() { ... }

// DELETE: registerEquateEndpoints() and handlers
private void registerEquateEndpoints() { ... }

// DELETE: registerNamespaceEndpoints() and handlers
private void registerNamespaceEndpoints() { ... }

// DELETE: registerProgramEndpoints() and handlers
private void registerProgramEndpoints() { ... }

// DELETE: registerSectionEndpoints() and handlers
private void registerSectionEndpoints() { ... }

// DELETE: registerSegmentEndpoints() and handlers
private void registerSegmentEndpoints() { ... }

// DELETE: registerVariableEndpoints() and handlers
private void registerVariableEndpoints() { ... }

// DELETE: registerCommentsEndpoints() and handlers
private void registerCommentsEndpoints() { ... }

// DELETE: registerAnalysisEndpoints() and handlers
private void registerAnalysisEndpoints() { ... }

// DELETE: registerClassEndpoints() and handlers
private void registerClassEndpoints() { ... }
```

**How to do this safely:**
1. Search for `private void register` - you'll find ~16 methods
2. For each one, delete the ENTIRE method including all its sub-handlers
3. Keep ONLY: `registerMetaEndpoints()` and `registerRootEndpoint()`

---

### STEP 6: Update Meta Endpoint Methods (45 minutes)

**KEEP** `registerSystemEndpoints()` but **RENAME** to `registerMetaEndpoints()` and update:

**Location**: `GhidraMCPHeadlessServer.java` lines ~127-178

**BEFORE:**
```java
private void registerSystemEndpoints() {
    // Root endpoint
    server.createContext("/", this::handleRoot);
    
    // Plugin version endpoint
    server.createContext("/plugin-version", this::handlePluginVersion);
    
    // Info endpoint
    server.createContext("/info", this::handleInfo);
}

private void handleRoot(HttpExchange exchange) throws IOException {
    Map<String, Object> response = new HashMap<>();
    response.put("success", true);
    response.put("message", "GhidraMCP Complete Headless API v2.0");
    response.put("mode", "headless");
    response.put("program", program.getName());
    response.put("endpoints", Arrays.asList(
        "/analysis", "/classes", "/comments", "/data", "/datatypes", "/equates",
        "/functions", "/memory", "/namespaces", "/program", "/segments",
        "/strings", "/symbols", "/variables", "/xrefs"
    ));
    sendJsonResponse(exchange, response, 200);
}
```

**AFTER:**
```java
private void registerMetaEndpoints(HttpServer server) {
    // Plugin version endpoint
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
    
    // Info endpoint
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
            infoData.put("instanceCount", activeInstances.size());
            
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
            // Check if this is actually a request for the root endpoint
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
            Program program = pluginState.getCurrentProgram();
            if (program != null) {
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

---

### STEP 7: Delete Utility Methods (30 minutes)

**DELETE THESE ENTIRE METHODS (lines ~1900-2037):**

```java
// DELETE ALL OF THESE:
private void logRequest(HttpExchange exchange) { ... }
private void safeHandle(...) { ... }
private void sendJsonResponse(...) { ... }
private void sendError(...) { ... }
private Map<String, String> parseQuery(String query) { ... }
private String toJson(Object obj) { ... }
private String mapToJson(Map<String, Object> map) { ... }
private String listToJson(List<?> list) { ... }
private String escapeJson(String str) { ... }
private Address parseAddressString(String addrStr) { ... }
// ... any other utility methods
```

**Why?** These are all handled by `HttpUtil` and `GhidraUtil` now.

---

### STEP 8: Add Public Methods for InstanceEndpoints (15 minutes)

**ADD THESE METHODS at the end of the class:**

```java
// ==================== PUBLIC METHODS FOR INSTANCE MANAGEMENT ====================

/**
 * Get the current program (for InstanceEndpoints).
 * @return the current program
 */
public Program getCurrentProgram() {
    return pluginState.getCurrentProgram();
}

/**
 * Check if this is the base instance (for InstanceEndpoints).
 * @return true if on default port
 */
public boolean isBaseInstance() {
    return port == ApiConstants.DEFAULT_PORT;
}

/**
 * Get the port this server is running on (for InstanceEndpoints).
 * @return the HTTP server port
 */
public int getPort() {
    return port;
}
```

---

### STEP 9: Update InstanceEndpoints.java (20 minutes)

**Location**: `src/main/java/au/federation/ghidra/endpoints/InstanceEndpoints.java`

**FIND** the `handleInstances()` method:

```java
private void handleInstances(HttpExchange exchange) throws IOException {
    try {
        List<Map<String, Object>> instanceData = new ArrayList<>();
        
        // Access the static activeInstances map from both plugin and script
        Map<Integer, Object> activeInstances = new HashMap<>();
        activeInstances.putAll(GhidraMCPPlugin.activeInstances);
        activeInstances.putAll(GhidraMCPHeadlessScript.activeInstances);  // OLD NAME
```

**UPDATE** the import and map access:

```java
import au.federation.ghidra.GhidraMCPHeadlessServer; // Update import

private void handleInstances(HttpExchange exchange) throws IOException {
    try {
        List<Map<String, Object>> instanceData = new ArrayList<>();
        
        // Access the static activeInstances map from both plugin and script
        Map<Integer, Object> activeInstances = new HashMap<>();
        activeInstances.putAll(GhidraMCPPlugin.activeInstances);
        activeInstances.putAll(GhidraMCPHeadlessServer.activeInstances); // NEW NAME
```

**UPDATE** the helper methods to recognize the new class:

```java
private boolean isBaseInstance(Object instance) {
    if (instance instanceof GhidraMCPPlugin) {
        return ((GhidraMCPPlugin) instance).isBaseInstance();
    } else if (instance instanceof GhidraMCPHeadlessServer) { // UPDATE THIS
        return ((GhidraMCPHeadlessServer) instance).isBaseInstance();
    }
    return false;
}

private Program getProgramFromInstance(Object instance) {
    if (instance instanceof GhidraMCPPlugin) {
        return ((GhidraMCPPlugin) instance).getCurrentProgram();
    } else if (instance instanceof GhidraMCPHeadlessServer) { // UPDATE THIS
        return ((GhidraMCPHeadlessServer) instance).getCurrentProgram();
    }
    return null;
}
```

**UPDATE** the mode detection:

```java
// Add mode info
if (instanceObj instanceof GhidraMCPPlugin) {
    instance.put("mode", "gui");
} else if (instanceObj instanceof GhidraMCPHeadlessServer) { // UPDATE THIS
    instance.put("mode", "headless");
} else {
    instance.put("mode", "unknown");
}
```

---

### STEP 10: Compile and Test (30 minutes)

**Compile:**
```powershell
mvn clean compile
```

**Expected Output:**
```
[INFO] BUILD SUCCESS
```

**If you get compilation errors:**
- Check all imports are correct
- Verify `HeadlessPluginState` is imported
- Ensure `activeInstances` is declared as `public static`

**Test Basic Startup:**
```powershell
$env:GHIDRA_INSTALL_DIR = "C:\ghidra_11.2.1"
& "$env:GHIDRA_INSTALL_DIR\support\analyzeHeadless.bat" `
    C:\temp\test_project test_proj `
    -import C:\path\to\binary.exe `
    -postScript GhidraMCPHeadlessServer.java
```

**Verify Endpoints:**
```powershell
# Test root endpoint
curl http://localhost:8192/

# Should return JSON with _links object
```

---

### STEP 11: Validation Tests (60 minutes)

**Create test script `test_parity.py`:**

```python
import requests
import json

BASE_URL = "http://localhost:8192"

def test_response_format(endpoint):
    """Verify response has HATEOAS format"""
    resp = requests.get(f"{BASE_URL}{endpoint}").json()
    
    assert 'id' in resp, f"{endpoint} missing 'id'"
    assert 'instance' in resp, f"{endpoint} missing 'instance'"
    assert 'success' in resp, f"{endpoint} missing 'success'"
    assert '_links' in resp, f"{endpoint} missing '_links'"
    
    print(f"✓ {endpoint} - Proper format")

def test_all_endpoints():
    """Test all critical endpoints"""
    endpoints = [
        "/",
        "/info",
        "/plugin-version",
        "/instances",
        "/program",
        "/functions",
        "/symbols",
        "/symbols/imports",
        "/symbols/exports",
        "/analysis",
        "/analysis/callgraph",
    ]
    
    for ep in endpoints:
        try:
            test_response_format(ep)
        except Exception as e:
            print(f"✗ {ep} - ERROR: {e}")

if __name__ == "__main__":
    test_all_endpoints()
```

**Run tests:**
```powershell
python test_parity.py
```

**Expected Output:**
```
✓ / - Proper format
✓ /info - Proper format
✓ /plugin-version - Proper format
✓ /instances - Proper format
...
```

---

### STEP 12: Performance Testing (30 minutes)

**Test with large binary:**
```python
import requests
import time

def test_pagination():
    """Verify pagination works"""
    start = time.time()
    resp = requests.get("http://localhost:8192/functions?limit=100").json()
    elapsed = time.time() - start
    
    assert len(resp['result']) <= 100
    assert elapsed < 1.0, f"Too slow: {elapsed}s"
    assert 'next' in resp['_links'] or 'prev' in resp['_links']
    
    print(f"✓ Pagination works ({elapsed:.2f}s)")

test_pagination()
```

---

## Troubleshooting Guide

### Error: "Class not found: HeadlessPluginState"

**Cause**: Missing import or not compiled  
**Fix**:
```powershell
mvn clean compile
```

### Error: "activeInstances cannot be resolved"

**Cause**: Field not declared as `public static`  
**Fix**: Ensure line 39 has:
```java
public static final Map<Integer, Object> activeInstances = new ConcurrentHashMap<>();
```

### Error: "ResponseBuilder cannot be resolved"

**Cause**: Missing import  
**Fix**: Add at top of file:
```java
import au.federation.ghidra.api.ResponseBuilder;
```

### Error: "No endpoints registered"

**Cause**: Endpoint registration order wrong  
**Fix**: Ensure root endpoint is registered LAST

### Response missing "_links" field

**Cause**: Not using ResponseBuilder  
**Fix**: Verify all meta endpoints use ResponseBuilder pattern

### Endpoints return 404

**Cause**: Path matching issue (most specific first)  
**Fix**: Check endpoint registration order matches GhidraMCPPlugin

---

## Verification Checklist

Before declaring success, verify:

- [ ] Compiles without errors
- [ ] Server starts without exceptions
- [ ] `GET /` returns JSON with `_links`
- [ ] `GET /info` returns proper HATEOAS format
- [ ] `GET /functions` returns paginated results with links
- [ ] `GET /symbols/imports` works (was missing before)
- [ ] `GET /analysis/callgraph` works (was missing before)
- [ ] `GET /instances` shows headless instance
- [ ] All responses have `id`, `instance`, `_links` fields
- [ ] Performance test passes (<1s for 100 functions)

---

## Post-Implementation

### Update Documentation
1. Update `README.md` with new capabilities
2. Update `GHIDRA_HTTP_API.md` with headless mode notes
3. Update example code to use new response format

### Git Commit
```powershell
git add .
git commit -m "Achieve feature parity between GUI and headless MCP servers

- Adopt HeadlessPluginState architecture
- Replace 1500 lines of inline handlers with endpoint classes
- Add ResponseBuilder for HATEOAS support
- Implement all 43 missing endpoints
- Add instance management support
- Code reduction: 68% fewer lines to maintain"

git push origin feature/headless-parity
```

### Create Pull Request
- Title: "Feature Parity: Headless MCP Server"
- Description: Link to `FEATURE_PARITY_PLAN.md`
- Reviewers: Team leads

---

## Success Metrics

After implementation, you should see:

**Code Metrics:**
- `GhidraMCPHeadlessServer.java`: ~450 lines (was 2037)
- Lines deleted: ~1500
- Lines added: ~100
- Code sharing: 95% (was 0%)

**Endpoint Coverage:**
- Total endpoints: 66 (was 23)
- Missing endpoints: 0 (was 43)
- Coverage: 100% (was 35%)

**Response Format:**
- HATEOAS support: 100% (was 0%)
- ResponseBuilder usage: 100% (was 0%)
- Format consistency: 100% (was ~30%)

---

## Time Estimates

| Step | Time | Cumulative |
|------|------|------------|
| 1. Backup | 5 min | 5 min |
| 2. Imports | 10 min | 15 min |
| 3. Fields | 15 min | 30 min |
| 4. run() | 30 min | 1 hr |
| 5. Delete handlers | 60 min | 2 hrs |
| 6. Meta endpoints | 45 min | 2h 45m |
| 7. Delete utils | 30 min | 3h 15m |
| 8. Public methods | 15 min | 3h 30m |
| 9. InstanceEndpoints | 20 min | 3h 50m |
| 10. Compile/test | 30 min | 4h 20m |
| 11. Validation | 60 min | 5h 20m |
| 12. Performance | 30 min | 5h 50m |

**Total: ~6 hours of focused work**

Split across 3 days:
- Day 1: Steps 1-6 (3 hours)
- Day 2: Steps 7-10 (2 hours)
- Day 3: Steps 11-12 + documentation (3 hours)

---

## Need Help?

**Common Issues:**
- See `ENDPOINT_COMPARISON_MATRIX.md` for endpoint details
- See `FEATURE_PARITY_PLAN.md` for architecture explanation
- Check existing endpoint classes for examples
- Review `GhidraMCPPlugin.java` for reference implementation

**Support:**
- GitHub Issues: Report bugs
- Discussions: Ask questions
- Pull Requests: Contribute improvements

Good luck! 🚀
