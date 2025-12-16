package au.federation.ghidra.endpoints;

// No direct JsonObject usage; relying on ResponseBuilder
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import au.federation.ghidra.api.ResponseBuilder;
import au.federation.ghidra.util.TransactionHelper;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.model.symbol.EquateReference;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.*;

/**
 * Endpoints for managing Equates (constant value name mappings) and their assignments to instruction operands.
 * Supports multiple equates per operand and auto-assignment during creation when address/operand parameters provided.
 */
public class EquateEndpoints extends AbstractEndpoint {

    public EquateEndpoints(au.federation.ghidra.PluginState pluginState) {
        super(pluginState);
    }

    @Override
    public void registerEndpoints(HttpServer server) {
        server.createContext("/equates", this::handleEquatesRoot);            // GET list, POST create (with optional auto-assign)
        server.createContext("/equates/", this::handleEquateByName);          // name-specific / usages sub-resource
        server.createContext("/equates/assign", this::handleAssign);          // explicit assign POST, DELETE to remove
        server.createContext("/equates/at/", this::handleEquatesAtAddress);   // listing at address
        server.createContext("/equates/value/", this::handleEquatesByValue);  // reverse lookup by numeric value
    }

    private void handleEquatesRoot(HttpExchange exchange) throws IOException {
        try {
            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 503, "No program is currently loaded", "NO_PROGRAM_LOADED");
                return;
            }
            String method = exchange.getRequestMethod();
            if ("GET".equals(method)) {
                handleListEquates(exchange, program);
                return;
            } else if ("POST".equals(method) || "PUT".equals(method)) {
                Map<String,String> body = parseJsonPostParams(exchange);
                handleCreateEquate(exchange, program, body);
                return;
            }
            sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
        } catch (Exception e) {
            Msg.error(this, "Error handling /equates", e);
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }

    private void handleEquateByName(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            if (path.equals("/equates") || path.equals("/equates/")) { // root handled elsewhere
                handleEquatesRoot(exchange);
                return;
            }
            // path after /equates/
            String tail = path.substring("/equates/".length());
            boolean usages = false;
            if (tail.endsWith("/usages")) {
                usages = true;
                tail = tail.substring(0, tail.length() - "/usages".length());
            }
            if (tail.isEmpty()) { // fallback
                sendErrorResponse(exchange, 404, "Equate not specified", "EQUATE_NOT_FOUND");
                return;
            }
            String equateName = decodeComponent(tail);

            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 503, "No program is currently loaded", "NO_PROGRAM_LOADED");
                return;
            }
            EquateTable eqTable = program.getEquateTable();
            Equate equate = eqTable.getEquate(equateName);
            if (equate == null) {
                sendErrorResponse(exchange, 404, "Equate not found: " + equateName, "EQUATE_NOT_FOUND");
                return;
            }

            String method = exchange.getRequestMethod();
            if (usages) {
                if (!"GET".equals(method)) {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                    return;
                }
                handleEquateUsages(exchange, program, equate);
                return;
            }

            if ("GET".equals(method)) {
                sendJsonResponse(exchange, buildEquateSummary(exchange, equate).build(), 200);
                return;
            } else if ("DELETE".equals(method)) {
                Map<String,String> q = parseQueryParams(exchange);
                boolean force = Boolean.parseBoolean(q.getOrDefault("force", "false"));
                handleDeleteEquate(exchange, program, equate, force);
                return;
            }
            sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
        } catch (Exception e) {
            Msg.error(this, "Error handling /equates/{name}", e);
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }

    private void handleAssign(HttpExchange exchange) throws IOException {
        try {
            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 503, "No program is currently loaded", "NO_PROGRAM_LOADED");
                return;
            }
            String method = exchange.getRequestMethod();
            if ("POST".equals(method)) {
                Map<String,String> body = parseJsonPostParams(exchange);
                assignEquate(exchange, program, body, false);
                return;
            } else if ("DELETE".equals(method)) {
                Map<String,String> body = parseJsonPostParams(exchange);
                removeEquateAssignment(exchange, program, body);
                return;
            }
            sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
        } catch (Exception e) {
            Msg.error(this, "Error handling /equates/assign", e);
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }

    private void handleEquatesAtAddress(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            if (!path.startsWith("/equates/at/")) {
                sendErrorResponse(exchange, 404, "Not Found", "NOT_FOUND");
                return;
            }
            String addrStr = path.substring("/equates/at/".length());
            if (addrStr.isEmpty()) {
                sendErrorResponse(exchange, 400, "Missing address", "MISSING_PARAMETER");
                return;
            }
            Program program = getCurrentProgram();
            if (program == null) { sendErrorResponse(exchange, 503, "No program is currently loaded", "NO_PROGRAM_LOADED"); return; }
            if (!"GET".equals(exchange.getRequestMethod())) { sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED"); return; }

            Address addr;
            try { addr = program.getAddressFactory().getAddress(addrStr); } catch (Exception ex) { sendErrorResponse(exchange, 400, "Invalid address", "INVALID_ADDRESS"); return; }
            Instruction instr = program.getListing().getInstructionAt(addr);
            if (instr == null) { sendErrorResponse(exchange, 404, "No instruction at address", "ADDRESS_NOT_FOUND"); return; }

            Map<String,String> q = parseQueryParams(exchange);
            Integer operandFilter = null;
            if (q.get("operandIndex") != null) {
                try { operandFilter = Integer.parseInt(q.get("operandIndex")); } catch (NumberFormatException nfe) { sendErrorResponse(exchange, 400, "Invalid operandIndex", "INVALID_PARAMETER"); return; }
            }

            EquateTable eqTable = program.getEquateTable();
            List<Map<String,Object>> result = new ArrayList<>();
            int operandCount = instr.getNumOperands();
            for (int opIndex = 0; opIndex < operandCount; opIndex++) {
                if (operandFilter != null && opIndex != operandFilter) continue;
                List<Equate> equates = eqTable.getEquates(addr, opIndex);
                if (equates != null && !equates.isEmpty()) {
                    Map<String,Object> item = new LinkedHashMap<>();
                    item.put("address", addr.toString());
                    item.put("operandIndex", opIndex);
                    List<String> names = new ArrayList<>();
                    for (Equate eq : equates) names.add(eq.getName());
                    item.put("names", names);
                    Map<String,Object> links = new LinkedHashMap<>();
                    links.put("instruction", Map.of("href", "/address/" + addr));
                    item.put("_links", links);
                    result.add(item);
                }
            }

            ResponseBuilder rb = new ResponseBuilder(exchange, getPort())
                .success(true)
                .result(result)
                .addLink("self", "/equates/at/" + addr);
            sendJsonResponse(exchange, rb.build(), 200);
        } catch (Exception e) {
            Msg.error(this, "Error handling /equates/at/{address}", e);
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }

    private void handleEquatesByValue(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            if (!path.startsWith("/equates/value/")) { sendErrorResponse(exchange, 404, "Not Found", "NOT_FOUND"); return; }
            String valueStr = path.substring("/equates/value/".length());
            if (valueStr.isEmpty()) { sendErrorResponse(exchange, 400, "Missing value", "MISSING_PARAMETER"); return; }
            Program program = getCurrentProgram();
            if (program == null) { sendErrorResponse(exchange, 503, "No program is currently loaded", "NO_PROGRAM_LOADED"); return; }
            if (!"GET".equals(exchange.getRequestMethod())) { sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED"); return; }

            long value;
            try { value = parseLongFlexible(valueStr); } catch (Exception ex) { sendErrorResponse(exchange, 400, "Invalid value", "INVALID_VALUE"); return; }
            EquateTable eqTable = program.getEquateTable();
            List<Equate> equates = eqTable.getEquates(value);
            List<Map<String,Object>> out = new ArrayList<>();
            if (equates != null) for (Equate eq : equates) out.add(equateMap(eq));
            ResponseBuilder rb = new ResponseBuilder(exchange, getPort())
                .success(true)
                .result(out)
                .addLink("self", "/equates/value/" + valueStr);
            sendJsonResponse(exchange, rb.build(), 200);
        } catch (Exception e) {
            Msg.error(this, "Error handling /equates/value/{value}", e);
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }

    private void handleListEquates(HttpExchange exchange, Program program) throws IOException {
        Map<String,String> q = parseQueryParams(exchange);
        int offset = parseIntOrDefault(q.get("offset"), 0);
        int limit = parseIntOrDefault(q.get("limit"), 100);
        String nameContains = q.get("nameContains");
        String valueStr = q.get("value");
        Long valueFilter = null;
        if (valueStr != null) {
            try { valueFilter = parseLongFlexible(valueStr); } catch (Exception ignored) {}
        }
        EquateTable eqTable = program.getEquateTable();
        Iterator<Equate> it = eqTable.getEquates();
        List<Equate> filtered = new ArrayList<>();
        while (it.hasNext()) {
            Equate e = it.next();
            if (nameContains != null && !e.getName().toLowerCase().contains(nameContains.toLowerCase())) continue;
            if (valueFilter != null && e.getValue() != valueFilter) continue;
            filtered.add(e);
        }
        // Sort by name ascending for now
        filtered.sort(Comparator.comparing(Equate::getName));

        // Pagination
        int start = Math.max(0, offset);
        int end = Math.min(filtered.size(), offset + limit);
        List<Map<String,Object>> slice = new ArrayList<>();
        for (int i = start; i < end; i++) slice.add(equateMap(filtered.get(i)));

        ResponseBuilder rb = new ResponseBuilder(exchange, getPort())
            .success(true)
            .result(slice)
            .addLink("self", "/equates?offset=" + offset + "&limit=" + limit);
        // Pagination metadata
        rb.metadata(Map.of("size", filtered.size(), "offset", offset, "limit", limit));
        sendJsonResponse(exchange, rb.build(), 200);
    }

    private void handleCreateEquate(HttpExchange exchange, Program program, Map<String,String> body) throws IOException {
        String name = body.get("name");
        String valueStr = body.get("value");
        if (name == null || name.isBlank()) { sendErrorResponse(exchange, 400, "Missing name", "MISSING_PARAMETER"); return; }
        if (valueStr == null || valueStr.isBlank()) { sendErrorResponse(exchange, 400, "Missing value", "MISSING_PARAMETER"); return; }
        long value;
        try { value = parseLongFlexible(valueStr); } catch (Exception ex) { sendErrorResponse(exchange, 400, "Invalid value", "INVALID_VALUE"); return; }

        // Optional auto-assign parameters
        String addrStr = body.get("address");
        String operandStr = body.get("operandIndex");
        boolean assign = addrStr != null && operandStr != null;

        Map<String,Object> result = new LinkedHashMap<>();
        result.put("name", name);
        result.put("value", value);
        result.put("valueHex", toHex(value));

        try {
            TransactionHelper.executeInTransaction(program, "Create Equate", () -> {
                EquateTable eqTable = program.getEquateTable();
                Equate existing = eqTable.getEquate(name);
                if (existing != null) {
                    if (existing.getValue() != value) {
                        throw new RuntimeException("Equate name exists with different value");
                    }
                } else {
                    eqTable.createEquate(name, value);
                    result.put("created", true);
                }
                return null;
            });
        } catch (TransactionHelper.TransactionException te) {
            sendErrorResponse(exchange, 409, "Equate value conflict", "EQUATE_VALUE_CONFLICT");
            return;
        } catch (RuntimeException re) {
            sendErrorResponse(exchange, 409, re.getMessage(), "EQUATE_VALUE_CONFLICT");
            return;
        }

        // Auto-assign if requested
        if (assign) {
            Map<String,String> assignBody = new HashMap<>();
            assignBody.put("name", name);
            assignBody.put("address", addrStr);
            assignBody.put("operandIndex", operandStr);
            assignBody.put("value", Long.toString(value)); // ensure consistent value
            // Use existing logic (will add assignment info to response separately?)
            try {
                // We'll perform assignment transaction separately
                Map<String,Object> assignmentInfo = performAssignment(program, assignBody, true);
                result.put("autoAssigned", true);
                result.put("assignment", assignmentInfo);
            } catch (Exception e) {
                result.put("autoAssigned", false);
                result.put("autoAssignError", e.getMessage());
            }
        }

        ResponseBuilder rb = new ResponseBuilder(exchange, getPort())
            .success(true)
            .result(result)
            .addLink("self", "/equates/" + encodeComponent(name))
            .addLink("assign", "/equates/assign")
            .addLink("usages", "/equates/" + encodeComponent(name) + "/usages");
        sendJsonResponse(exchange, rb.build(), 201);
    }

    private void assignEquate(HttpExchange exchange, Program program, Map<String,String> body, boolean internal) throws IOException {
        try {
            Map<String,Object> assignmentInfo = performAssignment(program, body, false);
            ResponseBuilder rb = new ResponseBuilder(exchange, getPort())
                .success(true)
                .result(assignmentInfo)
                .addLink("self", "/equates/assign")
                .addLink("equate", "/equates/" + encodeComponent((String) assignmentInfo.get("name")))
                .addLink("at_address", "/equates/at/" + assignmentInfo.get("address"));
            sendJsonResponse(exchange, rb.build(), 200);
        } catch (IllegalArgumentException iae) {
            sendErrorResponse(exchange, 400, iae.getMessage(), "INVALID_PARAMETER");
        } catch (NoSuchElementException nse) {
            sendErrorResponse(exchange, 404, nse.getMessage(), "NOT_FOUND");
        } catch (RuntimeException re) {
            sendErrorResponse(exchange, 409, re.getMessage(), "ASSIGNMENT_ERROR");
        } catch (Exception e) {
            Msg.error(this, "Unexpected error assigning equate", e);
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }

    private Map<String,Object> performAssignment(Program program, Map<String,String> body, boolean silent) throws Exception {
        String name = body.get("name");
        String addrStr = body.get("address");
        String operandStr = body.get("operandIndex");
        String valueStr = body.get("value"); // optional when equate exists
        if (name == null || addrStr == null || operandStr == null) throw new IllegalArgumentException("Missing required parameters: name, address, operandIndex");
        int operandIndex;
        try { operandIndex = Integer.parseInt(operandStr); } catch (NumberFormatException nfe) { throw new IllegalArgumentException("Invalid operandIndex"); }
    final long[] valueBox = new long[]{ -1L }; // mutable holder for lambda
        if (valueStr != null) {
            try { valueBox[0] = parseLongFlexible(valueStr); } catch (Exception ex) { throw new IllegalArgumentException("Invalid value"); }
        }
        Address addr;
        try { addr = program.getAddressFactory().getAddress(addrStr); } catch (Exception ex) { throw new IllegalArgumentException("Invalid address"); }
        Instruction instr = program.getListing().getInstructionAt(addr);
        if (instr == null) throw new NoSuchElementException("No instruction at address");
        if (operandIndex < 0 || operandIndex >= instr.getNumOperands()) throw new IllegalArgumentException("operandIndex out of range");

        Map<String,Object> result = new LinkedHashMap<>();
        result.put("name", name);
        result.put("address", addr.toString());
        result.put("operandIndex", operandIndex);

        TransactionHelper.executeInTransaction(program, "Assign Equate", () -> {
            EquateTable eqTable = program.getEquateTable();
            Equate eq = eqTable.getEquate(name);
            if (eq == null) {
                if (valueStr == null) throw new RuntimeException("Equate does not exist and value not provided");
                eq = eqTable.createEquate(name, valueBox[0]);
                result.put("created", true);
                if (valueBox[0] == -1) valueBox[0] = eq.getValue();
            } else {
                if (valueStr != null && eq.getValue() != valueBox[0]) throw new RuntimeException("Existing equate has different value");
                valueBox[0] = eq.getValue();
            }
            // Add reference; allow multiple equates per operand (do not remove existing)
            try {
                // symbol.Equate API addReference(Address,int)
                eq.addReference(addr, operandIndex);
            } catch (Exception ex) {
                throw new RuntimeException("Failed to add reference: " + ex.getMessage());
            }
            result.put("value", valueBox[0]);
            result.put("valueHex", toHex(valueBox[0]));
            return null;
        });
        return result;
    }

    private void removeEquateAssignment(HttpExchange exchange, Program program, Map<String,String> body) throws IOException {
        String name = body.get("name");
        String addrStr = body.get("address");
        String operandStr = body.get("operandIndex");
        if (name == null || addrStr == null || operandStr == null) { sendErrorResponse(exchange, 400, "Missing parameters", "MISSING_PARAMETER"); return; }
        int operandIndex;
        try { operandIndex = Integer.parseInt(operandStr); } catch (NumberFormatException nfe) { sendErrorResponse(exchange,400,"Invalid operandIndex","INVALID_PARAMETER"); return; }
        Address addr;
        try { addr = program.getAddressFactory().getAddress(addrStr); } catch (Exception ex) { sendErrorResponse(exchange,400,"Invalid address","INVALID_ADDRESS"); return; }
        try {
            TransactionHelper.executeInTransaction(program, "Remove Equate Assignment", () -> {
                EquateTable eqTable = program.getEquateTable();
                Equate eq = eqTable.getEquate(name);
                if (eq == null) throw new RuntimeException("Equate not found");
                boolean removed = false;
                // Equate API doesn't have direct remove by operand? Use removeReference
                try {
                    eq.removeReference(addr, operandIndex);
                    removed = true;
                } catch (Exception ex) {
                    throw new RuntimeException("Failed to remove reference: " + ex.getMessage());
                }
                if (!removed) throw new RuntimeException("Assignment not found");
                return null;
            });
        } catch (TransactionHelper.TransactionException te) {
            sendErrorResponse(exchange, 500, "Internal transaction error", "INTERNAL_ERROR");
            return;
        } catch (RuntimeException re) {
            sendErrorResponse(exchange, 404, re.getMessage(), "ASSIGNMENT_NOT_FOUND");
            return;
        }
        ResponseBuilder rb = new ResponseBuilder(exchange, getPort())
            .success(true)
            .result(Map.of(
                "removed", true,
                "name", name,
                "address", addrStr,
                "operandIndex", operandIndex
            ))
            .addLink("self", "/equates/assign")
            .addLink("equate", "/equates/" + encodeComponent(name));
        sendJsonResponse(exchange, rb.build(), 200);
    }

    private void handleEquateUsages(HttpExchange exchange, Program program, Equate equate) throws IOException {
        Map<String,String> q = parseQueryParams(exchange);
        int offset = parseIntOrDefault(q.get("offset"), 0);
        int limit = parseIntOrDefault(q.get("limit"), 100);
        List<Map<String,Object>> usages = new ArrayList<>();
        for (EquateReference ref : equate.getReferences()) {
            Map<String,Object> item = new LinkedHashMap<>();
            item.put("address", ref.getAddress().toString());
            item.put("operandIndex", ref.getOpIndex());
            Map<String,Object> links = new LinkedHashMap<>();
            links.put("instruction", Map.of("href", "/address/" + ref.getAddress()));
            item.put("_links", links);
            usages.add(item);
        }
        int start = Math.max(0, offset);
        int end = Math.min(usages.size(), offset + limit);
        List<Map<String,Object>> slice = usages.subList(start, end);
        ResponseBuilder rb = new ResponseBuilder(exchange, getPort())
            .success(true)
            .result(slice)
            .addLink("self", "/equates/" + encodeComponent(equate.getName()) + "/usages?offset=" + offset + "&limit=" + limit);
        rb.metadata(Map.of("size", usages.size(), "offset", offset, "limit", limit));
        sendJsonResponse(exchange, rb.build(), 200);
    }

    private void handleDeleteEquate(HttpExchange exchange, Program program, Equate equate, boolean force) throws IOException {
        try {
            TransactionHelper.executeInTransaction(program, "Delete Equate", () -> {
                if (!force && equate.getReferenceCount() > 0) {
                    throw new RuntimeException("Equate has usages");
                }
                if (force) {
                    // Remove all references first
                    for (EquateReference ref : equate.getReferences()) {
                        try { equate.removeReference(ref.getAddress(), ref.getOpIndex()); } catch (Exception ignore) {}
                    }
                }
                program.getEquateTable().removeEquate(equate.getName());
                return null;
            });
        } catch (RuntimeException re) {
            sendErrorResponse(exchange, 409, re.getMessage(), "EQUATE_IN_USE");
            return;
        } catch (TransactionHelper.TransactionException te) {
            sendErrorResponse(exchange, 500, "Internal transaction error", "INTERNAL_ERROR");
            return;
        }
        ResponseBuilder rb = new ResponseBuilder(exchange, getPort())
            .success(true)
            .result(Map.of("deleted", true, "name", equate.getName()))
            .addLink("self", "/equates")
            .addLink("list", "/equates");
        sendJsonResponse(exchange, rb.build(), 200);
    }

    private ResponseBuilder buildEquateSummary(HttpExchange exchange, Equate eq) {
        Map<String,Object> map = equateMap(eq);
        return new ResponseBuilder(exchange, getPort())
            .success(true)
            .result(map)
            .addLink("self", "/equates/" + encodeComponent(eq.getName()))
            .addLink("usages", "/equates/" + encodeComponent(eq.getName()) + "/usages")
            .addLink("assign", "/equates/assign");
    }

    private Map<String,Object> equateMap(Equate e) {
        Map<String,Object> m = new LinkedHashMap<>();
        m.put("name", e.getName());
        m.put("value", e.getValue());
        m.put("valueHex", toHex(e.getValue()));
        m.put("uses", e.getReferenceCount());
        Map<String,Object> links = new LinkedHashMap<>();
        links.put("self", Map.of("href", "/equates/" + encodeComponent(e.getName())));
        links.put("usages", Map.of("href", "/equates/" + encodeComponent(e.getName()) + "/usages"));
        m.put("_links", links);
        return m;
    }

    private long parseLongFlexible(String s) {
        s = s.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) return Long.parseLong(s.substring(2), 16);
        if (s.startsWith("-0x") || s.startsWith("-0X")) return -Long.parseLong(s.substring(3), 16);
        return Long.decode(s); // handles decimal, octal, hex with 0x
    }

    private String toHex(long v) { return String.format("0x%X", v); }

    private String encodeComponent(String c) { return java.net.URLEncoder.encode(c, java.nio.charset.StandardCharsets.UTF_8); }
    private String decodeComponent(String c) { return java.net.URLDecoder.decode(c, java.nio.charset.StandardCharsets.UTF_8); }
}
