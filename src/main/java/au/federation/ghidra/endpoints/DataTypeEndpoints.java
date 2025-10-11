package au.federation.ghidra.endpoints;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import au.federation.ghidra.api.ResponseBuilder;
import au.federation.ghidra.util.TransactionHelper;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Endpoints for managing DataTypes (Enums initially).
 */
public class DataTypeEndpoints extends AbstractEndpoint {

    private final PluginTool tool;

    public DataTypeEndpoints(Program program, int port, PluginTool tool) {
        super(program, port);
        this.tool = tool;
    }

    @Override
    protected PluginTool getTool() {
        return tool;
    }

    @Override
    public void registerEndpoints(HttpServer server) {
        server.createContext("/datatypes", this::handleDataTypes);
        server.createContext("/datatypes/enums", this::handleEnums);
        server.createContext("/datatypes/enums/", this::handleEnumByPath);
    }

    private void handleDataTypes(HttpExchange exchange) throws IOException {
        try {
            if (!"GET".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                return;
            }
            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                .success(true)
                .result(Map.of(
                    "message", "DataType API",
                    "supported", List.of("enums")
                ))
                .addLink("self", "/datatypes")
                .addLink("enums", "/datatypes/enums");
            sendJsonResponse(exchange, builder.build(), 200);
        } catch (Exception e) {
            Msg.error(this, "Error handling /datatypes", e);
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }

    // GET list, POST create
    private void handleEnums(HttpExchange exchange) throws IOException {
        try {
            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 503, "No program is currently loaded", "NO_PROGRAM_LOADED");
                return;
            }

            if ("GET".equals(exchange.getRequestMethod())) {
                DataTypeManager dtm = program.getDataTypeManager();
                List<Map<String, Object>> out = new ArrayList<>();
                for (ghidra.program.model.data.Enum en : collectEnums(dtm)) {
                    Map<String, Object> m = new HashMap<>();
                    m.put("name", en.getName());
                    m.put("category", en.getCategoryPath().getPath());
                    m.put("length", en.getLength());
                    out.add(m);
                }
                ResponseBuilder rb = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(out)
                    .addLink("self", "/datatypes/enums");
                sendJsonResponse(exchange, rb.build(), 200);
                return;
            }
            if ("POST".equals(exchange.getRequestMethod()) || "PUT".equals(exchange.getRequestMethod())) {
                Map<String, String> body = parseJsonPostParams(exchange);
                // Merge in query params as fallback
                Map<String, String> query = parseQueryParams(exchange);
                body.putIfAbsent("name", query.get("name"));
                body.putIfAbsent("category", query.get("category"));
                body.putIfAbsent("size", query.get("size"));
                body.putIfAbsent("members", query.get("members"));
                String name = body.get("name");
                String category = body.getOrDefault("category", "/");
                int size = parseIntOrDefault(body.get("size"), 4);
                if (name == null || name.isBlank()) {
                    sendErrorResponse(exchange, 400, "Missing enum name", "MISSING_PARAMETER");
                    return;
                }
                CategoryPath cat = toCategory(category);
                DataTypeManager dtm = program.getDataTypeManager();

                ghidra.program.model.data.Enum created = TransactionHelper.<ghidra.program.model.data.Enum>executeInTransaction(program, "Create Enum", () -> {
                    EnumDataType edt = new EnumDataType(cat, name, size, dtm);
                    // Optional: initial members
                    List<Map<String, String>> members = parseMembersList(body);
                    for (Map<String, String> it : members) {
                        String mn = it.get("name");
                        String mv = it.get("value");
                        if (mn != null && mv != null) {
                            try { edt.add(mn, parseLongSafe(mv, 0)); } catch (Exception ignore) {}
                        }
                    }
                    return (ghidra.program.model.data.Enum) dtm.addDataType(edt, DataTypeConflictHandler.DEFAULT_HANDLER);
                });

                ResponseBuilder rb = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(Map.of(
                        "name", created.getName(),
                        "category", created.getCategoryPath().getPath(),
                        "length", created.getLength()
                    ))
                    .addLink("self", "/datatypes/enums/" + urlEncode(created.getCategoryPath().getPath() + "/" + created.getName()));
                sendJsonResponse(exchange, rb.build(), 201);
                return;
            }
            sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
        } catch (Exception e) {
            Msg.error(this, "Error handling /datatypes/enums", e);
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }

    // GET details; POST/PUT/PATCH to create or add members; optional suffix /members
    // path: /datatypes/enums/{categoryPath/name} or /datatypes/enums/{categoryPath/name}/members
    private void handleEnumByPath(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            if (!path.startsWith("/datatypes/enums/")) {
                sendErrorResponse(exchange, 404, "Not Found", "NOT_FOUND");
                return;
            }
            String encoded = path.substring("/datatypes/enums/".length());
            String decoded = URLDecoder.decode(encoded, StandardCharsets.UTF_8);
            String enumPath = decoded;
            if (decoded.endsWith("/members")) {
                enumPath = decoded.substring(0, decoded.length() - "/members".length());
            } else if (decoded.endsWith("/constants")) {
                enumPath = decoded.substring(0, decoded.length() - "/constants".length());
            }

            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 503, "No program is currently loaded", "NO_PROGRAM_LOADED");
                return;
            }
            DataTypeManager dtm = program.getDataTypeManager();

            DataType dt = findEnumByCategoryAndName(dtm, enumPath);
            if (dt == null || !(dt instanceof ghidra.program.model.data.Enum)) {
                // If creating/updating via POST or PUT, create on demand
                if ("POST".equals(exchange.getRequestMethod()) || "PUT".equals(exchange.getRequestMethod())) {
                    // derive category and name from enumPath
                    String p = enumPath;
                    if (p.startsWith("/")) p = p.substring(1);
                    int idx = p.lastIndexOf('/');
                    String name = (idx >= 0) ? p.substring(idx + 1) : p;
                    String catPath = (idx >= 0) ? "/" + p.substring(0, idx) : "/";
                    CategoryPath cat = toCategory(catPath);
                    Map<String, String> body = parseJsonPostParams(exchange);
                    Map<String, String> query = parseQueryParams(exchange);
                    String sizeStr = (body != null) ? body.get("size") : null;
                    if (sizeStr == null && query != null) sizeStr = query.get("size");
                    final int fSize = parseIntOrDefault(sizeStr, 4);

                    ghidra.program.model.data.Enum created = TransactionHelper.<ghidra.program.model.data.Enum>executeInTransaction(program, "Create Enum", () -> {
                        EnumDataType edt = new EnumDataType(cat, name, fSize, dtm);
                        // Optional: initial members
                        List<Map<String, String>> members = parseMembersList(body);
                        for (Map<String, String> it : members) {
                            String mn = it.get("name");
                            String mv = it.get("value");
                            if (mn != null && mv != null) {
                                try { edt.add(mn, parseLongSafe(mv, 0)); } catch (Exception ignore) {}
                            }
                        }
                        return (ghidra.program.model.data.Enum) dtm.addDataType(edt, DataTypeConflictHandler.DEFAULT_HANDLER);
                    });
                    // refresh references
                    dt = created;
                } else {
                    sendErrorResponse(exchange, 404, "Enum not found: " + enumPath, "ENUM_NOT_FOUND");
                    return;
                }
            }
            ghidra.program.model.data.Enum en = (ghidra.program.model.data.Enum) dt;

            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, Object> res = new HashMap<>();
                res.put("name", en.getName());
                res.put("category", en.getCategoryPath().getPath());
                res.put("length", en.getLength());
                Map<String, Long> members = new LinkedHashMap<>();
                for (String n : en.getNames()) {
                    members.put(n, en.getValue(n));
                }
                res.put("members", members);

                ResponseBuilder rb = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(res)
                    .addLink("self", "/datatypes/enums/" + urlEncode(enumPath));
                sendJsonResponse(exchange, rb.build(), 200);
                return;
            }

            if ("PATCH".equals(exchange.getRequestMethod()) || "POST".equals(exchange.getRequestMethod()) || "PUT".equals(exchange.getRequestMethod())) {
                Map<String, String> body = parseJsonPostParams(exchange);
                // Merge in query params as fallback
                Map<String, String> query = parseQueryParams(exchange);
                body.putIfAbsent("name", query.get("name"));
                body.putIfAbsent("value", query.get("value"));
                body.putIfAbsent("members", query.get("members"));
                body.putIfAbsent("constants", query.get("constants"));

                List<Map<String, String>> items = parseMembersList(body);
                // Also support single name/value pair
                if (body.get("name") != null && body.get("value") != null) {
                    items.add(Map.of("name", body.get("name"), "value", body.get("value")));
                }

                if (items.isEmpty() && ("PATCH".equals(exchange.getRequestMethod()))) {
                    sendErrorResponse(exchange, 400, "Missing members to add", "MISSING_PARAMETER");
                    return;
                }

                ghidra.program.model.data.Enum updated = TransactionHelper.<ghidra.program.model.data.Enum>executeInTransaction(program, "Update Enum Members", () -> {
                    // Modify the managed Enum in-place to ensure persistence
                    for (Map<String, String> it : items) {
                        String n = it.get("name");
                        String vStr = it.get("value");
                        if (n == null || vStr == null) continue;
                        long v = parseLongSafe(vStr, 0);
                        try {
                            // If a constant with this name exists, replace its value
                            if (java.util.Arrays.asList(en.getNames()).contains(n)) {
                                try { en.remove(n); } catch (Exception ignore) {}
                            }
                            en.add(n, v);
                        } catch (Exception dup) {
                            // If duplicate value/name issues occur, attempt update by remove+add
                            try { en.remove(n); en.add(n, v); } catch (Exception ignoreAgain) {}
                        }
                    }
                    return en;
                });

                Map<String, Object> res = new HashMap<>();
                res.put("name", updated.getName());
                res.put("category", updated.getCategoryPath().getPath());
                Map<String, Long> members = new LinkedHashMap<>();
                for (String n : updated.getNames()) { members.put(n, updated.getValue(n)); }
                res.put("members", members);

                ResponseBuilder rb = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(res)
                    .addLink("self", "/datatypes/enums/" + urlEncode(enumPath));
                sendJsonResponse(exchange, rb.build(), 200);
                return;
            }

            sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
        } catch (Exception e) {
            Msg.error(this, "Error handling /datatypes/enums/{path}", e);
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }

    private CategoryPath toCategory(String category) {
        if (category == null || category.isBlank() || "/".equals(category)) return CategoryPath.ROOT;
        if (!category.startsWith("/")) category = "/" + category;
        return new CategoryPath(category);
    }

    private DataType findEnumByCategoryAndName(DataTypeManager dtm, String path) {
        // path format: /Category/Sub/Name or Name (in root)
        String p = path;
        if (p.startsWith("/")) p = p.substring(1);
        int idx = p.lastIndexOf('/');
        String name = (idx >= 0) ? p.substring(idx + 1) : p;
        String catPath = (idx >= 0) ? "/" + p.substring(0, idx) : "/";
        CategoryPath cat = toCategory(catPath);
        DataType dt = dtm.getDataType(cat, name);
        return (dt instanceof ghidra.program.model.data.Enum) ? dt : null;
    }

    private static String urlEncode(String s) {
        return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private long parseLongSafe(String s, long def) {
        try {
            if (s == null) return def;
            s = s.trim();
            // Support 0x/0X hex, octal, decimal via Long.decode
            return Long.decode(s);
        } catch (Exception e) {
            try { return Long.parseLong(s); } catch (Exception e2) { return def; }
        }
    }

    private List<ghidra.program.model.data.Enum> collectEnums(DataTypeManager dtm) {
        List<ghidra.program.model.data.Enum> out = new ArrayList<>();
        traverseCategory(dtm.getRootCategory(), out);
        return out;
    }

    private void traverseCategory(Category cat, List<ghidra.program.model.data.Enum> out) {
        if (cat == null) return;
        for (DataType dt : cat.getDataTypes()) {
            if (dt instanceof ghidra.program.model.data.Enum) {
                out.add((ghidra.program.model.data.Enum) dt);
            }
        }
        for (Category sub : cat.getCategories()) {
            traverseCategory(sub, out);
        }
    }

    private List<Map<String, String>> parseMembersList(Map<String, String> body) {
        List<Map<String, String>> items = new ArrayList<>();
        String membersJson = body.get("members");
        if ((membersJson == null || membersJson.isBlank()) && body.get("constants") != null) {
            membersJson = body.get("constants");
        }
        if ((membersJson == null || membersJson.isBlank()) && body.get("items") != null) {
            membersJson = body.get("items");
        }
        if (membersJson != null && !membersJson.isBlank()) {
            try {
                var arr = gson.fromJson(membersJson, com.google.gson.JsonArray.class);
                if (arr != null) {
                    for (var el : arr) {
                        var obj = el.getAsJsonObject();
                        String n = obj.has("name") ? obj.get("name").getAsString() : null;
                        String v = obj.has("value") ? (obj.get("value").isJsonPrimitive() ? obj.get("value").getAsString() : obj.get("value").toString()) : null;
                        if (n != null && v != null) { items.add(Map.of("name", n, "value", v)); }
                    }
                } else {
                    // Try as an object map: { CONST_NAME: value, ... }
                    var obj = gson.fromJson(membersJson, com.google.gson.JsonObject.class);
                    if (obj != null) {
                        for (var e : obj.entrySet()) {
                            String n = e.getKey();
                            String v = e.getValue().isJsonPrimitive() ? e.getValue().getAsString() : e.getValue().toString();
                            items.add(Map.of("name", n, "value", v));
                        }
                    }
                }
            } catch (Exception ignore) { /* malformed members JSON */ }
        }
        return items;
    }
}
