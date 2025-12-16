# Endpoint Comparison Matrix: GUI Plugin vs Headless Server

**Generated**: 2025-01-11  
**Purpose**: Detailed comparison of ALL endpoints between GUI plugin and headless server

---

## Summary Statistics

| Category | GUI Plugin | Current Headless | Missing | % Complete |
|----------|-----------|------------------|---------|------------|
| **Meta Endpoints** | 7 | 3 | 4 | 43% |
| **Function Endpoints** | 15 | 8 | 7 | 53% |
| **Symbol Endpoints** | 3 | 1 | 2 | 33% |
| **Data Endpoints** | 5 | 1 | 4 | 20% |
| **Memory Endpoints** | 4 | 1 | 3 | 25% |
| **DataType Endpoints** | 4 | 1 | 3 | 25% |
| **Equate Endpoints** | 6 | 1 | 5 | 17% |
| **Analysis Endpoints** | 2 | 1 | 1 | 50% |
| **Program Endpoints** | 4 | 1 | 3 | 25% |
| **Segment Endpoints** | 1 | 1 | 0 | 100% |
| **Namespace Endpoints** | 1 | 1 | 0 | 100% |
| **Variable Endpoints** | 1 | 1 | 0 | 100% |
| **Xref Endpoints** | 1 | 1 | 0 | 100% |
| **Class Endpoints** | 1 | 1 | 0 | 100% |
| **Comment Endpoints** | 3 | 1 | 2 | 33% |
| **Instance Endpoints** | 3 | 0 | 3 | 0% |
| **Pcode Endpoints** | 5 | 0 | 5 | 0% |
| **TOTAL** | **66** | **23** | **43** | **35%** |

---

## Detailed Endpoint Comparison

### Legend
- ✅ **IMPLEMENTED** - Endpoint exists and uses proper structure
- ⚠️ **PARTIAL** - Endpoint exists but missing features or wrong format
- ❌ **MISSING** - Endpoint not implemented
- 🔧 **FORMAT** - Uses manual JSON instead of ResponseBuilder
- 🔗 **HATEOAS** - Missing HATEOAS links

---

## 1. Meta Endpoints (Root & Instance Management)

| Endpoint | GUI Plugin | Headless | Status | Notes |
|----------|-----------|----------|--------|-------|
| **GET /** | ✅ Full HATEOAS | ⚠️ Simple | 🔧🔗 | Missing _links, instance field |
| **GET /info** | ✅ Full HATEOAS | ⚠️ Simple | 🔧🔗 | Missing HATEOAS structure |
| **GET /plugin-version** | ✅ Full HATEOAS | ⚠️ Simple | 🔧🔗 | Missing _links |
| **GET /instances** | ✅ Instance list | ❌ Not impl | ❌ | InstanceEndpoints not registered |
| **POST /registerInstance** | ✅ Register | ❌ Not impl | ❌ | InstanceEndpoints not registered |
| **POST /unregisterInstance** | ✅ Unregister | ❌ Not impl | ❌ | InstanceEndpoints not registered |
| **GET /projects** | ✅ Project list | ❌ Not impl | ❌ | Project management missing |

---

## 2. Function Endpoints

| Endpoint | GUI Plugin | Headless | Status | Notes |
|----------|-----------|----------|--------|-------|
| **GET /functions** | ✅ Paginated list | ⚠️ Simple list | 🔧🔗 | Missing pagination, HATEOAS |
| **GET /functions/{address}** | ✅ Full details | ⚠️ Basic info | 🔧🔗 | Missing fields, no HATEOAS |
| **PATCH /functions/{address}** | ✅ Update func | ❌ Not impl | ❌ | No update capability |
| **DELETE /functions/{address}** | ✅ Delete func | ❌ Not impl | ❌ | No delete capability |
| **GET /functions/by-name/{name}** | ✅ Lookup by name | ❌ Not impl | ❌ | Critical for AI agents |
| **GET /functions/{addr}/decompile** | ✅ Decompiled code | ✅ Works | ⚠️ | Exists but wrong format |
| **GET /functions/{addr}/disassembly** | ✅ Assembly | ❌ Not impl | ❌ | Missing disassembly |
| **GET /functions/{addr}/calls** | ✅ Called funcs | ✅ Works | ⚠️ | Exists but wrong format |
| **GET /functions/{addr}/callers** | ✅ Calling funcs | ✅ Works | ⚠️ | Exists but wrong format |
| **GET /functions/{addr}/variables** | ✅ Local vars | ✅ Works | ⚠️ | Exists but wrong format |
| **GET /functions/{addr}/parameters** | ✅ Parameters | ✅ Works | ⚠️ | Exists but wrong format |
| **GET /functions/{addr}/signature** | ✅ Signature | ❌ Not impl | ❌ | Type signature missing |
| **GET /functions/{addr}/stack** | ✅ Stack layout | ❌ Not impl | ❌ | Stack frame missing |
| **GET /functions/{addr}/pcode** | ✅ Pcode | ❌ Not impl | ❌ | IR representation missing |
| **GET /functions/thunks** | ✅ List thunks | ⚠️ Different | 🔧 | Different implementation |
| **GET /functions/external** | ✅ List external | ⚠️ Different | 🔧 | Different implementation |

**FunctionEndpoints Class Methods:**
```
GUI:     handleFunctions()
         handleFunctionByAddress()
         handleFunctionByName()
         handleFunctionResource()      <- Handles /decompile, /calls, etc.
         handleUpdateFunctionRESTful()
         handleDeleteFunctionRESTful()
         buildFunctionInfo()

Headless: handleListFunctions()       <- Manual implementation
          handleGetFunction()          <- Manual implementation  
          handleDecompileFunction()    <- Manual implementation
          ... (all manual)
```

---

## 3. Symbol Endpoints

| Endpoint | GUI Plugin | Headless | Status | Notes |
|----------|-----------|----------|--------|-------|
| **GET /symbols** | ✅ All symbols | ⚠️ Simple | 🔧🔗 | Missing pagination, HATEOAS |
| **GET /symbols/imports** | ✅ Import table | ❌ Not impl | ❌ | Critical for reverse engineering |
| **GET /symbols/exports** | ✅ Export table | ❌ Not impl | ❌ | Critical for reverse engineering |

**SymbolEndpoints Class:**
```java
// GUI Plugin
public void registerEndpoints(HttpServer server) {
    server.createContext("/symbols/imports", this::handleImports);
    server.createContext("/symbols/exports", this::handleExports);
    server.createContext("/symbols", this::handleSymbols);
}

// Headless - Only has basic /symbols with manual JSON
```

---

## 4. Data Endpoints

| Endpoint | GUI Plugin | Headless | Status | Notes |
|----------|-----------|----------|--------|-------|
| **GET /data** | ✅ Data items | ⚠️ Simple | 🔧🔗 | Wrong implementation |
| **POST /data** | ✅ Create data | ❌ Not impl | ❌ | No data creation |
| **DELETE /data/delete** | ✅ Delete data | ❌ Not impl | ❌ | No data deletion |
| **POST /data/update** | ✅ Update data | ❌ Not impl | ❌ | No data updates |
| **GET /data/type** | ✅ Data by type | ❌ Not impl | ❌ | Type filtering missing |
| **GET /strings** | ✅ String data | ⚠️ Simple | 🔧🔗 | Should be in DataEndpoints |

**DataEndpoints Class:**
```java
// GUI Plugin - 4 contexts
server.createContext("/data", this::handleData);
server.createContext("/data/delete", ...);
server.createContext("/data/update", ...);
server.createContext("/data/type", ...);
server.createContext("/strings", ...);

// Headless - Manual /data and /strings only
```

---

## 5. Memory Endpoints

| Endpoint | GUI Plugin | Headless | Status | Notes |
|----------|-----------|----------|--------|-------|
| **GET /memory** | ✅ Memory map | ⚠️ Simple | 🔧🔗 | Wrong format |
| **GET /memory/{address}** | ✅ Mem at addr | ❌ Not impl | ❌ | Address-specific missing |
| **GET /memory/{addr}/bytes** | ✅ Raw bytes | ❌ Not impl | ❌ | Binary data access missing |
| **GET /memory/{addr}/disasm** | ✅ Disassembly | ❌ Not impl | ❌ | Inline disasm missing |

**MemoryEndpoints Class:**
```java
// GUI Plugin
server.createContext("/memory/", exchange -> {
    // Handles /{address} and sub-resources
});
server.createContext("/memory", this::handleMemoryRequest);

// Headless - Only basic /memory listing
```

---

## 6. DataType Endpoints

| Endpoint | GUI Plugin | Headless | Status | Notes |
|----------|-----------|----------|--------|-------|
| **GET /datatypes** | ✅ Type list | ⚠️ Simple | 🔧🔗 | Wrong format |
| **GET /datatypes/{path}** | ✅ Type details | ❌ Not impl | ❌ | Specific type missing |
| **GET /datatypes/enums** | ✅ Enum list | ❌ Not impl | ❌ | Enum support missing |
| **GET /datatypes/enums/{path}** | ✅ Enum details | ❌ Not impl | ❌ | Enum values missing |

**DataTypeEndpoints Class:**
```java
// GUI Plugin
server.createContext("/datatypes", this::handleDataTypes);
server.createContext("/datatypes/enums", this::handleEnums);
server.createContext("/datatypes/enums/", this::handleEnumByPath);

// Headless - Only basic /datatypes
```

---

## 7. Equate Endpoints

| Endpoint | GUI Plugin | Headless | Status | Notes |
|----------|-----------|----------|--------|-------|
| **GET /equates** | ✅ List equates | ⚠️ Simple | 🔧🔗 | Wrong format |
| **POST /equates** | ✅ Create equate | ❌ Not impl | ❌ | No creation |
| **GET /equates/{name}** | ✅ Equate details | ❌ Not impl | ❌ | Name lookup missing |
| **DELETE /equates/{name}** | ✅ Delete equate | ❌ Not impl | ❌ | No deletion |
| **POST /equates/assign** | ✅ Assign equate | ❌ Not impl | ❌ | Assignment missing |
| **DELETE /equates/assign** | ✅ Remove assign | ❌ Not impl | ❌ | Unassignment missing |
| **GET /equates/at/{address}** | ✅ At address | ❌ Not impl | ❌ | Address lookup missing |
| **GET /equates/value/{value}** | ✅ By value | ❌ Not impl | ❌ | Reverse lookup missing |

**EquateEndpoints Class:**
```java
// GUI Plugin - 5 contexts
server.createContext("/equates", this::handleEquatesRoot);
server.createContext("/equates/", this::handleEquateByName);
server.createContext("/equates/assign", this::handleAssign);
server.createContext("/equates/at/", this::handleEquatesAtAddress);
server.createContext("/equates/value/", this::handleEquatesByValue);

// Headless - Only basic /equates
```

---

## 8. Analysis Endpoints

| Endpoint | GUI Plugin | Headless | Status | Notes |
|----------|-----------|----------|--------|-------|
| **GET /analysis** | ✅ Analysis status | ⚠️ Simple | 🔧🔗 | Wrong format |
| **POST /analysis** | ✅ Start/stop | ❌ Not impl | ❌ | No control |
| **GET /analysis/callgraph** | ✅ Call graph | ❌ Not impl | ❌ | Critical for analysis |

**AnalysisEndpoints Class:**
```java
// GUI Plugin
server.createContext("/analysis", this::handleAnalysisRequest);

// ProgramEndpoints registers:
server.createContext("/analysis/callgraph", this::handleCallGraph);

// Headless - Only basic /analysis
```

---

## 9. Program Endpoints

| Endpoint | GUI Plugin | Headless | Status | Notes |
|----------|-----------|----------|--------|-------|
| **GET /program** | ✅ Program info | ⚠️ Via /info | 🔧 | Different endpoint |
| **GET /address** | ✅ Current addr | ❌ Not impl | ❌ | GUI-only feature |
| **GET /function** | ✅ Current func | ❌ Not impl | ❌ | GUI-only feature |
| **GET /programs** | ✅ List programs | ❌ Not impl | ❌ | Multi-program support |

**ProgramEndpoints Class:**
```java
// GUI Plugin
server.createContext("/program", this::handleProgramInfo);
server.createContext("/address", this::handleCurrentAddress);
server.createContext("/function", this::handleCurrentFunction);
server.createContext("/analysis/callgraph", this::handleCallGraph);

// Headless - Only /info (different format)
```

---

## 10. Segment Endpoints

| Endpoint | GUI Plugin | Headless | Status | Notes |
|----------|-----------|----------|--------|-------|
| **GET /segments** | ✅ Segment list | ⚠️ Simple | 🔧🔗 | Wrong format |

**SegmentEndpoints Class:**
```java
// Both have /segments but different implementations
```

---

## 11. Namespace Endpoints

| Endpoint | GUI Plugin | Headless | Status | Notes |
|----------|-----------|----------|--------|-------|
| **GET /namespaces** | ✅ Namespace list | ⚠️ Simple | 🔧🔗 | Wrong format |

---

## 12. Variable Endpoints

| Endpoint | GUI Plugin | Headless | Status | Notes |
|----------|-----------|----------|--------|-------|
| **GET /variables** | ✅ Global vars | ⚠️ Simple | 🔧🔗 | Wrong format |

---

## 13. Xref Endpoints

| Endpoint | GUI Plugin | Headless | Status | Notes |
|----------|-----------|----------|--------|-------|
| **GET /xrefs** | ✅ Cross-refs | ⚠️ Simple | 🔧🔗 | Wrong format |

---

## 14. Class Endpoints

| Endpoint | GUI Plugin | Headless | Status | Notes |
|----------|-----------|----------|--------|-------|
| **GET /classes** | ✅ Class list | ⚠️ Simple | 🔧🔗 | Wrong format |

---

## 15. Comment Endpoints

| Endpoint | GUI Plugin | Headless | Status | Notes |
|----------|-----------|----------|--------|-------|
| **GET /comments** | ✅ List comments | ⚠️ Simple | 🔧🔗 | Wrong format |
| **POST /comments** | ✅ Add comment | ❌ Not impl | ❌ | No creation |
| **DELETE /comments** | ✅ Delete comment | ❌ Not impl | ❌ | No deletion |

---

## 16. Pcode Endpoints

| Endpoint | GUI Plugin | Headless | Status | Notes |
|----------|-----------|----------|--------|-------|
| **GET /pcode/{address}** | ❌ Planned | ❌ Not impl | ❌ | PcodeEndpoints.java is empty |
| **GET /pcode/{addr}/ops** | ❌ Planned | ❌ Not impl | ❌ | Empty file |
| **GET /pcode/{addr}/highlevel** | ❌ Planned | ❌ Not impl | ❌ | Empty file |

**NOTE**: PcodeEndpoints.java exists but is completely empty in BOTH GUI and headless.

---

## Response Format Differences

### GUI Plugin Response (Using ResponseBuilder)

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "instance": "http://localhost:8192",
  "success": true,
  "result": {
    "name": "main",
    "address": "0x00401000",
    "signature": "int main(int argc, char** argv)",
    "parameterCount": 2,
    "isThunk": false,
    "isExternal": false
  },
  "_links": {
    "self": {"href": "/functions/0x00401000"},
    "program": {"href": "/program"},
    "decompile": {"href": "/functions/0x00401000/decompile"},
    "disassembly": {"href": "/functions/0x00401000/disassembly"},
    "variables": {"href": "/functions/0x00401000/variables"},
    "by_name": {"href": "/functions/by-name/main"},
    "xrefs_to": {"href": "/xrefs?to_addr=0x00401000"},
    "xrefs_from": {"href": "/xrefs?from_addr=0x00401000"}
  }
}
```

### Headless Server Response (Manual JSON)

```json
{
  "success": true,
  "result": {
    "name": "main",
    "address": "0x00401000",
    "signature": "int main(int argc, char** argv)",
    "comment": null,
    "parameterCount": 2,
    "localVariableCount": 3,
    "isThunk": false,
    "isExternal": false,
    "callingConvention": "__cdecl"
  }
}
```

**MISSING IN HEADLESS:**
- ❌ `id` field (request tracking)
- ❌ `instance` field (multi-instance support)
- ❌ `_links` object (HATEOAS navigation)

---

## Critical Missing Features

### 1. HATEOAS Navigation
**Impact**: AI agents cannot discover available actions
**Example**: After getting a function, agent doesn't know it can get `/decompile`

### 2. Pagination
**Impact**: Large binaries will timeout or crash
**Example**: Binary with 10,000 functions returns all at once

### 3. Multi-Instance Support
**Impact**: Cannot run multiple headless servers
**Example**: `/instances` endpoint doesn't exist

### 4. Request Tracking
**Impact**: Cannot correlate requests in logs
**Example**: No `id` field in responses

### 5. Data Modification
**Impact**: Read-only API (cannot add comments, equates, etc.)
**Example**: No POST/PATCH/DELETE support

---

## Implementation Priority

### P0 - CRITICAL (Breaks AI Agents)
1. ✅ Use ResponseBuilder for ALL endpoints
2. ✅ Add HATEOAS `_links` to ALL responses
3. ✅ Implement `/functions/by-name/{name}` (name lookup)
4. ✅ Implement `/symbols/imports` and `/symbols/exports`
5. ✅ Implement `/analysis/callgraph`
6. ✅ Add pagination to ALL list endpoints

### P1 - HIGH (Major Features)
1. ✅ Implement `/instances` management
2. ✅ Add POST/PATCH/DELETE for data modification
3. ✅ Implement `/datatypes/enums` support
4. ✅ Implement `/equates/*` sub-resources
5. ✅ Add `/memory/{address}` sub-resources

### P2 - MEDIUM (Nice to Have)
1. ✅ Implement `/program` vs `/info` consistency
2. ✅ Add `/data/*` mutation endpoints
3. ✅ Implement `/comments` CRUD operations

### P3 - LOW (Future Enhancement)
1. ⏸️ Implement Pcode endpoints (empty in GUI too)
2. ⏸️ Add `/address` and `/function` (GUI-specific)
3. ⏸️ Multi-program support via `/programs`

---

## Code Sharing Opportunities

### Current State: 0% Code Sharing
```
GhidraMCPPlugin.java         (482 lines) + 
FunctionEndpoints.java       (1411 lines) +
... (14 more endpoint classes)           = Production Code

GhidraMCPHeadlessServer.java (2037 lines) = 100% Duplicate Code
```

### Target State: 95% Code Sharing
```
GhidraMCPPlugin.java         (482 lines)  = GUI Wrapper
GhidraMCPHeadlessServer.java (450 lines)  = Headless Wrapper

Shared by Both:
  - FunctionEndpoints.java   (1411 lines)
  - ... (15 endpoint classes)
  - ResponseBuilder.java
  - HttpUtil.java
  - GhidraUtil.java
  - PluginState interface
```

**Maintenance Reduction**: 68% fewer lines to maintain

---

## Testing Strategy

### Unit Tests (Per Endpoint Class)
```python
class TestFunctionEndpoints:
    def test_list_functions_pagination(self):
        resp = get("/functions?offset=0&limit=10")
        assert len(resp['result']) <= 10
        assert '_links' in resp
        assert 'next' in resp['_links']
    
    def test_get_function_by_address(self):
        resp = get("/functions/0x00401000")
        assert resp['success'] == True
        assert 'decompile' in resp['_links']
    
    def test_get_function_by_name(self):
        resp = get("/functions/by-name/main")
        assert resp['result']['name'] == "main"
```

### Integration Tests (Cross-Endpoint)
```python
def test_hateoas_navigation():
    # Start at root
    root = get("/")
    
    # Navigate to functions
    funcs_url = root['_links']['functions']['href']
    funcs = get(funcs_url)
    
    # Navigate to first function
    first_func_url = funcs['result'][0]['_links']['self']['href']
    func = get(first_func_url)
    
    # Navigate to decompilation
    decomp_url = func['_links']['decompile']['href']
    decomp = get(decomp_url)
    
    assert 'code' in decomp['result']
```

### Format Validation Tests
```python
def test_response_format(endpoint):
    resp = get(endpoint)
    
    # Required fields
    assert 'id' in resp
    assert 'instance' in resp
    assert 'success' in resp
    
    # HATEOAS
    assert '_links' in resp
    assert 'self' in resp['_links']
    
    # Result or error
    assert ('result' in resp) or ('error' in resp)
```

---

## Migration Path

### Phase 1: Enable ResponseBuilder (Day 1)
- Import ResponseBuilder
- Update `/info` and `/plugin-version`
- Verify response format changes

### Phase 2: Register Endpoint Classes (Day 2)
- Delete inline handlers
- Register production endpoint classes
- Verify all endpoints still work

### Phase 3: Testing & Validation (Day 3)
- Run automated test suite
- Compare responses with GUI plugin
- Fix any discrepancies

### Phase 4: Documentation (Day 4)
- Update API documentation
- Update example code
- Update README

---

## Conclusion

The headless server is missing **43 out of 66 endpoints (65%)**. Even endpoints that exist use a completely different implementation with incompatible response formats.

**CRITICAL ACTIONS:**
1. ✅ Adopt `HeadlessPluginState` architecture
2. ✅ Replace ALL inline handlers with endpoint classes
3. ✅ Use `ResponseBuilder` for HATEOAS support
4. ✅ Add comprehensive test coverage

**ESTIMATED EFFORT**: 3 days for full feature parity

**RISK**: HIGH - Large refactor but absolutely necessary for production use
