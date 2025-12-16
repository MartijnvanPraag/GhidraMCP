# GhidraMCP Endpoint Parity Inventory
**Date:** October 12, 2025  
**Purpose:** Document differences between GUI and Headless endpoint implementations  
**Status:** Analysis Complete - Action Items Identified

---

## Executive Summary

### Critical Finding: Memory Endpoint Response Mismatch ✅ FIXED
- **Issue:** Headless `/memory?address=...` was returning memory blocks info instead of memory read data
- **Impact:** MCP server network_config tools completely broken
- **Status:** **FIXED** - Routing logic updated to check query parameters
- **Verification:** ✅ USER CONFIRMED WORKING

### Recent Implementations ✅
1. **Memory Read Endpoint** - ✅ FIXED and USER VERIFIED
2. **Memory Blocks Endpoint** - ✅ FIXED and COMPILED (awaiting user testing)
3. **Memory Comments Endpoint** - ✅ NEWLY IMPLEMENTED (GET and POST support)

### Additional Analysis Required
This inventory documents the current state and identifies areas requiring verification.

---

## 1. MEMORY ENDPOINTS

### 1.1 `/memory` (Query Parameter Based)
**GUI Implementation:** `MemoryEndpoints.java` - Lines 56-175

**Request Format:**
```
GET /memory?address=005F1000&length=1024&format=base64
```

**GUI Response Structure:**
```json
{
  "id": "e3ce04ea-2fe6-4776-b57a-6fc34d2363ac",
  "instance": "http://localhost:8192",
  "success": true,
  "result": {
    "address": "005f1000",
    "bytesRead": 1024,
    "rawBytes": "Vovx9kQkCAHHBmCFYgB0C2oIVuiYAAEAg8QIi8ZewgQADx...",
    "hexBytes": "56 8B F1 F6 44 24 08 01 C7 06 60 85 62 00 74 0B..."
  },
  "_links": {
    "self": { "href": "/memory?address=005f1000&length=1024&format=base64" },
    "program": { "href": "/program" },
    "blocks": { "href": "/memory/blocks" },
    "next": { "href": "/memory?address=005f1400&length=1024" },
    "prev": { "href": "/memory?address=005f0c00&length=1024" }
  }
}
```

**Headless Implementation:** `GhidraMCPHeadlessServer.java` - Lines 1135-1228

**Key Fields Analysis:**

| Field | GUI | Headless (FIXED) | Match? |
|-------|-----|------------------|--------|
| `address` | ✅ String (lowercase hex) | ✅ String (via toString()) | ✅ VERIFY |
| `bytesRead` | ✅ Integer | ✅ Integer (changed from "length") | ✅ FIXED |
| `rawBytes` | ✅ Base64 string | ✅ Base64 (always included) | ✅ FIXED |
| `hexBytes` | ✅ Uppercase with spaces | ✅ Uppercase with spaces | ✅ FIXED |
| `_links.self` | ✅ Full query params | ✅ Full query params | ✅ FIXED |
| `_links.program` | ✅ Present | ✅ Present | ✅ |
| `_links.blocks` | ✅ Present | ✅ Present | ✅ FIXED |
| `_links.next` | ✅ Present | ✅ Present | ✅ FIXED |
| `_links.prev` | ✅ Conditional | ✅ Conditional | ✅ FIXED |

**Status:** ✅ **FIXED - NEEDS TESTING**

**Action Items:**
1. ⚠️ **VERIFY:** Test actual headless response with user's query
2. ⚠️ **VERIFY:** Confirm address formatting matches (lowercase vs uppercase)
3. ⚠️ **VERIFY:** Confirm hex byte spacing is exactly "XX XX XX" format

---

### 1.2 `/memory/blocks`
**GUI Implementation:** `MemoryEndpoints.java` - Lines 364-432

**GUI Response Structure:**
```json
{
  "id": "...",
  "instance": "http://localhost:8192",
  "success": true,
  "result": [
    {
      "name": "Headers",
      "start": "005f0000",
      "end": "005f03ff",
      "size": 1024,
      "permissions": "r---",
      "isInitialized": true,
      "isLoaded": true,
      "isMapped": true
    }
  ],
  "total": 6,
  "offset": 0,
  "limit": 100,
  "_links": {
    "self": { "href": "/memory/blocks?offset=0&limit=100" },
    "program": { "href": "/program" },
    "memory": { "href": "/memory" },
    "next": { "href": "/memory/blocks?offset=100&limit=100" },
    "prev": { "href": "/memory/blocks?offset=0&limit=100" }
  }
}
```

**Headless Implementation:** `GhidraMCPHeadlessServer.java` - Lines 1329-1398

**Key Fields Analysis:**

| Field | GUI | Headless (FIXED) | Match? |
|-------|-----|------------------|--------|
| `name` | ✅ String | ✅ String | ✅ |
| `start` | ✅ String (lowercase hex) | ✅ String (via toString()) | ✅ |
| `end` | ✅ String (lowercase hex) | ✅ String (via toString()) | ✅ |
| `size` | ✅ Long | ✅ Long | ✅ |
| `permissions` | ✅ "rwxv" format | ✅ "rwxv" format | ✅ FIXED |
| `isInitialized` | ✅ Boolean | ✅ Boolean | ✅ FIXED |
| `isLoaded` | ✅ Boolean | ✅ Boolean | ✅ FIXED |
| `isMapped` | ✅ Boolean | ✅ Boolean | ✅ FIXED |
| Pagination | ✅ offset/limit | ✅ offset/limit | ✅ FIXED |
| `total` metadata | ✅ Present | ✅ Present | ✅ FIXED |

**Status:** ✅ **FIXED - NEEDS TESTING**

**Changes Made:**
1. Created dedicated `handleMemoryBlocks()` method
2. Uses 4-character permission string: "rwxv" (read, write, execute, volatile)
3. Field names match GUI exactly: `isInitialized`, `isLoaded`, `isMapped`
4. Implements offset/limit pagination (not page/per_page)
5. Returns paginated results with metadata
6. HATEOAS links with next/prev pagination

**Action Items:**
1. ⚠️ **VERIFY:** Test `/memory/blocks` endpoint with and without pagination
2. ⚠️ **VERIFY:** Confirm permissions string format matches exactly
3. ⚠️ **VERIFY:** Test pagination next/prev links work correctly

---

### 1.3 `/memory/{address}/comments/{type}`
**GUI Implementation:** `MemoryEndpoints.java` - Lines 182-220

**Headless Implementation:** ✅ `GhidraMCPHeadlessServer.java` - Lines 1408-1573

**Request Format:**
```
GET /memory/{address}/comments/{type}
POST /memory/{address}/comments/{type}
Body: {"comment": "This is a comment"}
```

**Supported Comment Types:**
- `plate` - Plate comment (default)
- `pre` - Pre comment
- `post` - Post comment
- `eol` - End-of-line comment
- `repeatable` - Repeatable comment

**GUI Response Structure (GET):**
```json
{
  "id": "...",
  "instance": "http://localhost:8192",
  "success": true,
  "result": {
    "address": "005f1000",
    "comment_type": "plate",
    "comment": "This is a plate comment"
  },
  "_links": {
    "self": { "href": "/memory/005f1000/comments/plate" },
    "memory": { "href": "/memory" },
    "program": { "href": "/program" }
  }
}
```

**Headless Implementation:** ✅ COMPLETE

**Key Features Implemented:**
1. ✅ GET endpoint to retrieve comments by type
2. ✅ POST endpoint to set comments (with transaction support)
3. ✅ All 5 comment types supported (plate, pre, post, eol, repeatable)
4. ✅ Proper address validation
5. ✅ HATEOAS response structure with links
6. ✅ Error handling for invalid addresses, types, and missing parameters
7. ✅ Transaction management for comment updates

**Status:** ✅ **IMPLEMENTED - NEEDS TESTING**

**Action Items:**
1. ⚠️ **VERIFY:** Test GET `/memory/{address}/comments/{type}` endpoint
2. ⚠️ **VERIFY:** Test POST `/memory/{address}/comments/{type}` endpoint with comment data
3. ⚠️ **VERIFY:** Confirm all 5 comment types work correctly
4. ⚠️ **VERIFY:** Test error handling for invalid addresses and types

---

## 2. PROGRAM ENDPOINTS

### 2.1 `/program` (Current Program Info)
**GUI Implementation:** `ProgramEndpoints.java` - Lines 263-310

**GUI Response Structure:**
```json
{
  "id": "...",
  "instance": "http://localhost:8192",
  "success": true,
  "result": {
    "programId": "project:path",
    "name": "program.dll",
    "isOpen": true,
    // ... ProgramInfo fields
  },
  "_links": {
    "self": { "href": "/program" },
    "project": { "href": "/projects/{name}" },
    "functions": { "href": "/functions" },
    "symbols": { "href": "/symbols" },
    "data": { "href": "/data" },
    "segments": { "href": "/segments" },
    "memory": { "href": "/memory" },
    "xrefs": { "href": "/xrefs" },
    "analysis": { "href": "/analysis" }
  }
}
```

**Headless Implementation:** ❌ **NOT VERIFIED**

**Status:** ⚠️ **NEEDS VERIFICATION**

**Action Items:**
1. ❌ **TODO:** Check headless `/program` response structure
2. ❌ **TODO:** Verify ProgramInfo fields match GUI
3. ❌ **TODO:** Confirm all HATEOAS links present
4. ❌ **TODO:** Check if "project" link is included (may not apply in headless)

---

### 2.2 `/address` (Current Address)
**GUI Implementation:** `ProgramEndpoints.java` - Line 42

**Headless Implementation:** ❌ **NOT IMPLEMENTED**

**Status:** ❌ **MISSING ENDPOINT**

**Action Items:**
1. ❌ **TODO:** Implement `/address` endpoint in headless
2. ❌ **TODO:** Return currently selected address from UI context (if applicable)

---

### 2.3 `/function` (Current Function)
**GUI Implementation:** `ProgramEndpoints.java` - Line 43

**Headless Implementation:** ❌ **NOT IMPLEMENTED**

**Status:** ❌ **MISSING ENDPOINT**

**Action Items:**
1. ❌ **TODO:** Implement `/function` endpoint in headless
2. ❌ **TODO:** Return currently selected function from UI context (if applicable)

---

### 2.4 `/analysis/callgraph`
**GUI Implementation:** `ProgramEndpoints.java` - Line 46

**Headless Implementation:** ✅ Implemented in analysis endpoints

**Status:** ⚠️ **NEEDS VERIFICATION**

**Action Items:**
1. ❌ **TODO:** Compare response structures between GUI and headless
2. ❌ **TODO:** Verify parameter handling matches

---

## 3. FUNCTION ENDPOINTS

### 3.1 `/functions` (List)
**Status:** ✅ **LIKELY OK** - Both use pagination

**Action Items:**
1. ⚠️ **VERIFY:** Field names match exactly
2. ⚠️ **VERIFY:** Pagination metadata structure matches

---

### 3.2 `/functions/by-name/{name}`
**GUI Implementation:** Unknown if exists

**Headless Implementation:** ✅ Implemented - Lines 790-856

**Status:** ⚠️ **VERIFY GUI HAS THIS**

**Action Items:**
1. ❌ **TODO:** Check if GUI has `/functions/by-name/{name}` endpoint
2. ⚠️ **VERIFY:** If GUI has it, compare response structures

---

### 3.3 `/functions/{address}/decompile`
**Status:** ✅ **LIKELY OK**

**Action Items:**
1. ⚠️ **VERIFY:** Response field names match (code, function, address)
2. ⚠️ **VERIFY:** Error handling matches for timeout cases

---

## 4. SYMBOL ENDPOINTS

### 4.1 `/symbols/imports`
**Headless Implementation:** ✅ Implemented with pagination

**Status:** ⚠️ **NEEDS VERIFICATION**

**Action Items:**
1. ❌ **TODO:** Compare response field names with GUI
2. ❌ **TODO:** Verify pagination uses offset/limit not page/per_page

---

### 4.2 `/symbols/exports`
**Headless Implementation:** ✅ Implemented with pagination

**Status:** ⚠️ **NEEDS VERIFICATION**

**Action Items:**
1. ❌ **TODO:** Compare response field names with GUI
2. ❌ **TODO:** Verify pagination parameters match

---

## 5. SEGMENTS/SECTIONS ENDPOINTS

### 5.1 `/segments` vs `/sections` Naming
**Issue:** GUI uses `/segments`, Headless used `/sections`

**Resolution:** ✅ **FIXED** - Headless now supports BOTH:
- `/segments` - GUI compatible endpoint
- `/sections` - Original headless endpoint

**Status:** ✅ **FIXED - NEEDS TESTING**

---

### 5.2 `/segments/by-name/{name}/read`
**GUI Implementation:** ❌ **NOT PRESENT**

**Headless Implementation:** ✅ Implemented for both `/segments` and `/sections`

**Status:** ✅ **HEADLESS HAS MORE FEATURES**

**Note:** This is a headless enhancement - GUI doesn't have this capability

---

## 6. DATA ENDPOINTS

### 6.1 `/data` (List)
**Status:** ⚠️ **NEEDS VERIFICATION**

**Action Items:**
1. ❌ **TODO:** Compare response structures
2. ❌ **TODO:** Verify field names match
3. ❌ **TODO:** Check pagination parameter style

---

## 7. XREFS ENDPOINTS

### 7.1 `/xrefs?address={addr}`
**Status:** ⚠️ **NEEDS VERIFICATION**

**Action Items:**
1. ❌ **TODO:** Verify response structure matches
2. ❌ **TODO:** Check field names: `references_to` vs `referencesTo`
3. ❌ **TODO:** Verify reference type formatting

---

## 8. STRINGS ENDPOINTS

### 8.1 `/strings`
**Status:** ⚠️ **NEEDS VERIFICATION**

**Action Items:**
1. ❌ **TODO:** Compare pagination styles
2. ❌ **TODO:** Verify filter parameters match
3. ❌ **TODO:** Check response field names

---

## 9. CRITICAL DIFFERENCES IDENTIFIED

### 9.1 Pagination Style Inconsistency

**GUI Pattern (observed):**
- Uses `offset` and `limit` parameters
- Metadata: `{ offset: 0, limit: 100 }`

**Headless Pattern (current):**
- Some use `page` and `per_page`
- Some use `offset` and `limit`
- **INCONSISTENT!**

**Status:** ⚠️ **NEEDS STANDARDIZATION**

**Action Items:**
1. ❌ **TODO:** Audit ALL headless endpoints for pagination style
2. ❌ **TODO:** Standardize to match GUI pattern (offset/limit)
3. ❌ **TODO:** Update affected endpoints:
   - `/functions` - uses page/per_page ❌
   - `/symbols` - uses page/per_page ❌
   - `/data` - uses page/per_page ❌
   - `/strings` - uses page/per_page ❌

---

### 9.2 Field Naming Convention

**Observed Patterns:**

| Concept | GUI Style | Headless Style | Consistent? |
|---------|-----------|----------------|-------------|
| Bytes read count | `bytesRead` | `bytesRead` (fixed) | ✅ |
| Reference lists | Unknown | `references_to` | ⚠️ Verify |
| Pagination offset | `offset` | Mixed | ❌ |
| Pagination limit | `limit` | Mixed (`per_page`) | ❌ |

**Action Items:**
1. ❌ **TODO:** Create comprehensive field name mapping document
2. ❌ **TODO:** Identify all snake_case vs camelCase inconsistencies
3. ❌ **TODO:** Standardize to match GUI convention

---

### 9.3 HATEOAS Link Structure

**GUI Pattern:**
```json
"_links": {
  "self": { "href": "/endpoint" },
  "next": { "href": "/endpoint?offset=100" }
}
```

**Headless Pattern:**
```json
"_links": {
  "self": { "href": "/endpoint" },
  "next": { "href": "/endpoint?offset=100" }
}
```

**Status:** ✅ **APPEARS CONSISTENT**

**Action Items:**
1. ⚠️ **VERIFY:** All endpoints use consistent link structure
2. ⚠️ **VERIFY:** No endpoints use flat string hrefs

---

## 10. MISSING GUI ENDPOINTS IN HEADLESS

### High Priority (Likely Used by MCP Tools)

1. ❌ `/address` - Current address endpoint
2. ❌ `/function` - Current function endpoint

### Medium Priority

3. ⚠️ Additional program management endpoints

---

## 11. ADDITIONAL HEADLESS FEATURES NOT IN GUI

### Enhancements (Keep These!)

1. ✅ `/segments/by-name/{name}/read` - Section data reading
2. ✅ `/sections/by-name/{name}/read` - Alternative section reading
3. ✅ Both `/segments` and `/sections` support

---

## 12. TESTING CHECKLIST

### Phase 1: Critical Path (Memory Endpoints) ✅ READY FOR TESTING
- [x] Fix `/memory?address=...` routing ✅ COMPLETED
- [x] Fix `/memory/blocks` implementation ✅ COMPLETED
- [x] Implement `/memory/{address}/comments/{type}` endpoint ✅ COMPLETED
- [ ] Test `/memory?address=...` with actual headless server ✅ USER CONFIRMED WORKING
- [ ] Test `/memory/blocks` with actual headless server
- [ ] Test `/memory/{address}/comments/{type}` GET endpoint
- [ ] Test `/memory/{address}/comments/{type}` POST endpoint
- [ ] Verify all 5 comment types work (plate, pre, post, eol, repeatable)
- [ ] Verify responses match GUI byte-for-byte
- [ ] Confirm MCP tools work correctly

### Phase 2: Field Name Audit
- [ ] Extract all response field names from GUI endpoints
- [ ] Extract all response field names from headless endpoints
- [ ] Create side-by-side comparison
- [ ] Identify mismatches
- [ ] Create fix plan

### Phase 3: Pagination Standardization
- [ ] Audit all list endpoints in headless
- [ ] Change `page`/`per_page` to `offset`/`limit`
- [ ] Update metadata structures
- [ ] Test pagination thoroughly

### Phase 4: Missing Endpoints
- [ ] Implement `/memory/{address}/comments/{type}`
- [ ] Implement `/address` (if needed)
- [ ] Implement `/function` (if needed)
- [ ] Verify `/memory/blocks` compatibility

### Phase 5: Integration Testing
- [ ] Test all network_config_discover dependencies
- [ ] Test all network_config_extract dependencies
- [ ] Full MCP server integration test
- [ ] Performance testing

---

## 13. RECOMMENDATIONS

### Immediate Actions (Before Next Test)
1. **User should test current memory endpoint fix** ✅
2. Wait for feedback before proceeding

### Short Term (Next Session)
1. **Standardize pagination** across all endpoints
2. **Field name audit** - create comprehensive mapping
3. **Implement missing comment endpoints**

### Medium Term
1. **Create automated comparison tests** between GUI and headless
2. **Document all endpoint differences** in API specification
3. **Create test suite** that validates response schemas

### Long Term
1. **Shared response builder** between GUI and headless
2. **Common test framework** for both implementations
3. **Automated schema validation** in CI/CD

---

## 14. RISK ASSESSMENT

### High Risk Issues
1. ❌ **Pagination inconsistency** - May break MCP tools that paginate results
2. ✅ **Memory endpoint** - FIXED, but needs verification
3. ❌ **Field naming** - Unknown extent of snake_case vs camelCase issues

### Medium Risk Issues
1. ⚠️ Missing `/memory/blocks` alignment
2. ⚠️ Unknown GUI endpoint implementations
3. ⚠️ HATEOAS link variations

### Low Risk Issues
1. Missing UI-context endpoints (`/address`, `/function`) - May not be needed in headless
2. Extra features in headless - These are enhancements

---

## 15. CONCLUSION

### Summary of Findings

**FIXED:**
- ✅ Memory read endpoint routing ✅ USER CONFIRMED WORKING
- ✅ Memory read response structure (bytesRead, hexBytes format, HATEOAS links) ✅ USER CONFIRMED WORKING
- ✅ Memory blocks endpoint - Complete rewrite to match GUI format
- ✅ Memory comments endpoint - Full GET/POST implementation with all comment types
- ✅ Segments endpoint aliasing

**NEEDS VERIFICATION:**
- ⚠️ Memory endpoint output format in actual deployment
- ⚠️ All other endpoint response structures
- ⚠️ Field naming conventions

**NEEDS IMPLEMENTATION:**
- ❌ Pagination standardization (page/per_page → offset/limit)
- ❌ Memory comments endpoint
- ❌ Field name consistency fixes

**CRITICAL NEXT STEP:**
👉 **User must test the fixed memory endpoint before proceeding further**

Once memory endpoint is confirmed working, we can proceed with systematic verification of all other endpoints.

---

## Appendix A: Quick Reference

### Pagination Conversion Guide
```
OLD (Headless - Wrong):
?page=1&per_page=50

NEW (Match GUI):
?offset=0&limit=50

Conversion:
offset = (page - 1) * per_page
limit = per_page
```

### Common Field Mappings
```
bytesRead ✅ (both use this)
hexBytes ✅ (both use this)
rawBytes ✅ (both use this)
offset/limit ⚠️ (headless inconsistent)
```

---

**Document Version:** 1.0  
**Last Updated:** October 12, 2025  
**Next Review:** After memory endpoint testing  
**Owner:** GhidraMCP Development Team
