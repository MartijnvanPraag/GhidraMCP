/* Complete GhidraMCP Headless Server with ALL endpoints
 * Feature parity with GUI MCP server
 * @category GhidraMCP
 */
//@category GhidraMCP
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.util.*;
import ghidra.program.util.*;
import ghidra.app.decompiler.*;
import ghidra.app.util.bin.format.pe.*;
import ghidra.util.task.*;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import com.sun.net.httpserver.*;
import java.net.InetSocketAddress;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.Base64;

import au.federation.ghidra.api.ApiConstants;
import au.federation.ghidra.util.GhidraUtil;

/**
 * GhidraMCP Headless Server
 * Provides HTTP API for MCP integration in headless mode
 */
public class GhidraMCPHeadlessServer extends GhidraScript {
    
    private static HttpServer server;
    private Program program;
    private DecompInterface decompiler;
    private int port = 8192;
    private long serverStartTime;
    private final Gson gson = new Gson();
    
    // Instance tracking for multi-instance support
    private static final Map<Integer, GhidraMCPHeadlessServer> activeInstances = new ConcurrentHashMap<>();
    
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
        
        // In headless mode with existing projects, the program might not be automatically loaded
        // First try getCurrentProgram()
        program = getCurrentProgram();
        
        // If no program is loaded and we have arguments, try to open the specified program
        if (program == null && getScriptArgs().length > 0) {
            String programName = getScriptArgs()[0];
            println("No current program, attempting to open: " + programName);
            
            // Try to open the program from the project
            try {
                ghidra.framework.model.Project project = state.getProject();
                if (project != null) {
                    ghidra.framework.model.ProjectData projectData = project.getProjectData();
                    
                    // Ensure program name starts with '/' for Ghidra's absolute path requirement
                    String programPath = programName.startsWith("/") ? programName : "/" + programName;
                    println("Looking for program at path: " + programPath);
                    
                    ghidra.framework.model.DomainFile programFile = projectData.getFile(programPath);
                    
                    if (programFile != null) {
                        println("Found program file in project: " + programFile.getName());
                        program = (Program) programFile.getDomainObject(this, false, false, monitor);
                        println("Successfully opened program: " + program.getName());
                    } else {
                        println("ERROR: Program file not found in project: " + programPath);
                        println("Listing all files in project root:");
                        // Try to list files to help debug
                        for (ghidra.framework.model.DomainFile df : projectData.getRootFolder().getFiles()) {
                            println("  - " + df.getPathname());
                        }
                    }
                }
            } catch (Exception e) {
                println("ERROR: Failed to open program: " + e.getMessage());
                e.printStackTrace();
            }
        }
        
        // If still null, try state.getCurrentProgram()
        if (program == null && state != null) {
            println("Trying state.getCurrentProgram()...");
            program = state.getCurrentProgram();
        }
        
        if (program == null) {
            println("ERROR: No program is currently open!");
            println("This can happen if:");
            println("  1. No program was specified");
            println("  2. The specified program doesn't exist in the project");
            println("  3. Failed to open the program");
            println("");
            println("Usage: Run with program name as argument:");
            println("  -postScript GhidraMCPHeadlessServer.java <program_name>");
            return;
        }
        
        // Initialize decompiler
        decompiler = new DecompInterface();
        decompiler.openProgram(program);
        
        // Register this instance
        activeInstances.put(port, this);
        
        println("===========================================");
        println("GhidraMCP Complete Headless Server");
        println("===========================================");
        println("Program: " + program.getName());
        println("Port: " + port);
        println("===========================================");
        
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
            serverStartTime = System.currentTimeMillis();
            println("Complete MCP server started on port " + port);
            println("All endpoints are available!");
            
            // Keep running
            String keepRunning = System.getenv("GHIDRAMCP_KEEP_RUNNING");
            if (keepRunning == null || "true".equalsIgnoreCase(keepRunning)) {
                println("Server running. Press Ctrl+C to stop.");
                
                while (!monitor.isCancelled()) {
                    Thread.sleep(1000);
                }
            }
            
        } catch (Exception e) {
            println("ERROR: Failed to start server: " + e.getMessage());
            e.printStackTrace();
        } finally {
            if (decompiler != null) {
                decompiler.dispose();
            }
            if (server != null) {
                server.stop(0);
                println("Server stopped.");
            }
            // Unregister this instance
            activeInstances.remove(port);
        }
    }
    
    // ==================== SYSTEM ENDPOINTS ====================
    private void registerSystemEndpoints() {
        // Root endpoint
        server.createContext("/", this::handleRoot);
        
        // Plugin version endpoint
        server.createContext("/plugin-version", this::handlePluginVersion);
        
        // Info endpoint
        server.createContext("/info", this::handleInfo);
        
        // Instances endpoint
        server.createContext("/instances", this::handleInstances);
    }
    
    private void handleRoot(HttpExchange exchange) throws IOException {
        String requestId = getRequestId(exchange);

        Map<String, Object> rootData = new LinkedHashMap<>();
        rootData.put("message", "GhidraMCP API " + ApiConstants.API_VERSION);
        rootData.put("documentation", "See GHIDRA_HTTP_API.md for full API documentation");
        rootData.put("isBaseInstance", isBaseInstance());

        HeadlessResponseBuilder builder = new HeadlessResponseBuilder(requestId)
            .success(true)
            .result(rootData)
            .addLink("self", "/")
            .addLink("info", "/info")
            .addLink("plugin-version", "/plugin-version")
            .addLink("projects", "/projects")
            .addLink("instances", "/instances")
            .addLink("programs", "/programs");

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
                   .addLink("equates", "/equates");
        }

        sendJsonResponse(exchange, builder.build(), 200);
    }
    
    private void handlePluginVersion(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            return;
        }

        String requestId = getRequestId(exchange);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("plugin_version", ApiConstants.PLUGIN_VERSION);
        result.put("api_version", ApiConstants.API_VERSION);

        HeadlessResponseBuilder builder = new HeadlessResponseBuilder(requestId)
            .success(true)
            .result(result)
            .addLink("self", "/plugin-version")
            .addLink("root", "/");

        sendJsonResponse(exchange, builder.build(), 200);
    }
    
    private void handleInfo(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            return;
        }

        String requestId = getRequestId(exchange);
        Map<String, Object> infoData = new LinkedHashMap<>();
        infoData.put("isBaseInstance", isBaseInstance());

        if (program != null) {
            infoData.put("file", program.getName());
            infoData.put("architecture", program.getLanguage().getLanguageID().getIdAsString());
            infoData.put("processor", program.getLanguage().getProcessor().toString());
            infoData.put("addressSize", program.getAddressFactory().getDefaultAddressSpace().getSize());
            infoData.put("creationDate", program.getCreationDate());
            infoData.put("executable", program.getExecutablePath());
        }

        ghidra.framework.model.Project project = state != null ? state.getProject() : null;
        if (project != null) {
            infoData.put("project", project.getName());
            infoData.put("projectLocation", project.getProjectLocator().toString());
        }

        infoData.put("serverPort", port);
        infoData.put("serverStartTime", serverStartTime);
        infoData.put("instanceCount", activeInstances.size());

        HeadlessResponseBuilder builder = new HeadlessResponseBuilder(requestId)
            .success(true)
            .result(infoData)
            .addLink("self", "/info")
            .addLink("root", "/")
            .addLink("instances", "/instances");

        if (program != null) {
            builder.addLink("program", "/program");
        }

        sendJsonResponse(exchange, builder.build(), 200);
    }
    
    private void handleInstances(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            return;
        }

        String requestId = getRequestId(exchange);
        List<Map<String, Object>> instances = new ArrayList<>();

        for (Map.Entry<Integer, GhidraMCPHeadlessServer> entry : activeInstances.entrySet()) {
            int instancePort = entry.getKey();
            GhidraMCPHeadlessServer instance = entry.getValue();

            Map<String, Object> instanceInfo = new LinkedHashMap<>();
            instanceInfo.put("port", instancePort);
            instanceInfo.put("url", "http://localhost:" + instancePort);
            instanceInfo.put("mode", "headless");
            instanceInfo.put("isBase", instance.isBaseInstance());

            Program prog = instance.getCurrentProgram();
            if (prog != null) {
                instanceInfo.put("program", prog.getName());
                instanceInfo.put("programPath", prog.getExecutablePath());
            }

            Map<String, Object> instanceLinks = new LinkedHashMap<>();
            instanceLinks.put("self", Map.of("href", "/instances/" + instancePort));
            instanceLinks.put("info", Map.of("href", "http://localhost:" + instancePort + "/info"));
            instanceLinks.put("connect", Map.of("href", "http://localhost:" + instancePort));
            instanceInfo.put("_links", instanceLinks);

            instances.add(instanceInfo);
        }

        HeadlessResponseBuilder builder = new HeadlessResponseBuilder(requestId)
            .success(true)
            .result(instances)
            .addLink("self", "/instances")
            .addLink("register", "/registerInstance", "POST")
            .addLink("unregister", "/unregisterInstance", "POST")
            .addLink("programs", "/programs");

        sendJsonResponse(exchange, builder.build(), 200);
    }
    
    // ==================== FUNCTION ENDPOINTS ====================
    private void registerFunctionEndpoints() {
        // Register by-name endpoint first (most specific)
        server.createContext("/functions/by-name/", this::handleFunctionByName);
        
        // Single smart router for all /functions/* paths
        server.createContext("/functions", exchange -> {
            safeHandle(exchange, ex -> {
                String method = ex.getRequestMethod();
                String path = ex.getRequestURI().getPath();
                String query = ex.getRequestURI().getQuery();

                String[] segments = path.split("/");
                boolean baseEndpoint = segments.length <= 2 || (segments.length == 3 && segments[2].isEmpty());

                if (baseEndpoint) {
                    if ("GET".equals(method)) {
                        handleListFunctions(ex, query);
                    } else {
                        sendError(ex, 405, "Method not allowed", "METHOD_NOT_ALLOWED");
                    }
                    return;
                }

                if (segments.length >= 3) {
                    String addressOrAction = segments[2];

                    if (segments.length == 3 || (segments.length == 4 && segments[3].isEmpty())) {
                        if ("thunks".equals(addressOrAction)) {
                            if (!"GET".equals(method)) {
                                sendError(ex, 405, "Method not allowed", "METHOD_NOT_ALLOWED");
                                return;
                            }
                            handleThunkFunctions(ex);
                            return;
                        }

                        if ("external".equals(addressOrAction)) {
                            if (!"GET".equals(method)) {
                                sendError(ex, 405, "Method not allowed", "METHOD_NOT_ALLOWED");
                                return;
                            }
                            handleExternalFunctions(ex);
                            return;
                        }

                        if ("GET".equals(method)) {
                            handleGetFunction(ex, addressOrAction);
                        } else if ("PATCH".equals(method)) {
                            handleUpdateFunction(ex, addressOrAction);
                        } else if ("DELETE".equals(method)) {
                            handleDeleteFunction(ex, addressOrAction);
                        } else {
                            sendError(ex, 405, "Method not allowed", "METHOD_NOT_ALLOWED");
                        }
                        return;
                    }

                    if (segments.length >= 4) {
                        String action = segments[3];
                        if (!"GET".equals(method)) {
                            sendError(ex, 405, "Method not allowed", "METHOD_NOT_ALLOWED");
                            return;
                        }

                        switch (action) {
                            case "decompile":
                                handleDecompileFunction(ex, addressOrAction);
                                break;
                            case "calls":
                                handleFunctionCalls(ex, addressOrAction);
                                break;
                            case "callers":
                                handleFunctionCallers(ex, addressOrAction);
                                break;
                            case "disassembly":
                                handleFunctionDisassembly(ex, addressOrAction);
                                break;
                            case "variables":
                                handleFunctionVariables(ex, addressOrAction);
                                break;
                            case "parameters":
                                handleFunctionParameters(ex, addressOrAction);
                                break;
                            default:
                                sendError(ex, 404, "Unknown function action: " + action, "RESOURCE_NOT_FOUND");
                        }
                        return;
                    }
                }

                sendError(ex, 404, "Invalid function endpoint path", "RESOURCE_NOT_FOUND");
            });
        });
    }
    
    private void handleListFunctions(HttpExchange exchange, String query) throws IOException {
        String requestId = getRequestId(exchange);
        Map<String, String> params = parseQuery(query);

        int offset = parseIntOrDefault(params.get("offset"), 0);
        int limit = parseIntOrDefault(params.get("limit"), 100);

        Program currentProgram = getCurrentProgram();
        if (currentProgram == null) {
            sendError(exchange, 503, "No program is currently loaded", "NO_PROGRAM_LOADED");
            return;
        }

        String nameFilter = params.get("name");
        String nameContainsFilter = params.get("name_contains");
        String nameRegexFilter = params.get("name_matches_regex");
        String addrFilter = params.get("addr");

        FunctionManager funcMgr = currentProgram.getFunctionManager();
        List<Map<String, Object>> allFunctions = new ArrayList<>();

        FunctionIterator iter = funcMgr.getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();

            if (nameFilter != null && !func.getName().equals(nameFilter)) {
                continue;
            }
            if (nameContainsFilter != null && !func.getName().toLowerCase().contains(nameContainsFilter.toLowerCase())) {
                continue;
            }
            if (nameRegexFilter != null && !func.getName().matches(nameRegexFilter)) {
                continue;
            }
            if (addrFilter != null && !func.getEntryPoint().toString().equals(addrFilter)) {
                continue;
            }

            Map<String, Object> funcData = new LinkedHashMap<>();
            funcData.put("address", func.getEntryPoint().toString());

            Map<String, Object> funcLinks = new LinkedHashMap<>();
            Map<String, Object> selfLink = new LinkedHashMap<>();
            selfLink.put("href", "/functions/" + func.getEntryPoint().toString());
            funcLinks.put("self", selfLink);

            Map<String, Object> programLink = new LinkedHashMap<>();
            programLink.put("href", "/program");
            funcLinks.put("program", programLink);

            funcData.put("_links", funcLinks);
            funcData.put("name", func.getName());

            allFunctions.add(funcData);
        }

        int totalSize = allFunctions.size();
        int endIndex = Math.min(totalSize, offset + limit);
        List<Map<String, Object>> paginatedFunctions = offset < totalSize
            ? allFunctions.subList(offset, endIndex)
            : new ArrayList<>();

        HeadlessResponseBuilder builder = new HeadlessResponseBuilder(requestId)
            .success(true)
            .result(paginatedFunctions)
            .metadata("size", totalSize)
            .metadata("offset", offset)
            .metadata("limit", limit);

        builder.addLink("self", "/functions?offset=" + offset + "&limit=" + limit);

        if (endIndex < totalSize) {
            builder.addLink("next", "/functions?offset=" + endIndex + "&limit=" + limit);
        }

        if (offset > 0) {
            int prevOffset = Math.max(0, offset - limit);
            builder.addLink("prev", "/functions?offset=" + prevOffset + "&limit=" + limit);
        }

        builder.addLink("create", "/functions", "POST");

        sendJsonResponse(exchange, builder.build(), 200);
    }
    
    private void handleGetFunction(HttpExchange exchange, String addrStr) throws Exception {
        String requestId = getRequestId(exchange);
        Program currentProgram = getCurrentProgram();
        if (currentProgram == null) {
            sendError(exchange, 503, "No program is currently loaded", "NO_PROGRAM_LOADED");
            return;
        }

        Address addr = parseAddressString(addrStr);
        Function func = currentProgram.getFunctionManager().getFunctionAt(addr);

        if (func == null) {
            sendError(exchange, 404, "Function not found at " + addrStr, "FUNCTION_NOT_FOUND");
            return;
        }

        Map<String, Object> result = buildFunctionInfoMap(func);

        HeadlessResponseBuilder builder = new HeadlessResponseBuilder(requestId)
            .success(true)
            .result(result)
            .addLink("self", "/functions/" + func.getEntryPoint().toString())
            .addLink("program", "/program")
            .addLink("decompile", "/functions/" + func.getEntryPoint().toString() + "/decompile")
            .addLink("disassembly", "/functions/" + func.getEntryPoint().toString() + "/disassembly")
            .addLink("variables", "/functions/" + func.getEntryPoint().toString() + "/variables")
            .addLink("by_name", "/functions/by-name/" + func.getName())
            .addLink("xrefs_to", "/xrefs?to_addr=" + func.getEntryPoint().toString())
            .addLink("xrefs_from", "/xrefs?from_addr=" + func.getEntryPoint().toString());

        sendJsonResponse(exchange, builder.build(), 200);
    }

    private Map<String, Object> buildFunctionInfoMap(Function func) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("name", func.getName());
        result.put("address", func.getEntryPoint().toString());
        result.put("signature", func.getSignature().getPrototypeString());

        if (func.getReturnType() != null) {
            result.put("returnType", func.getReturnType().getName());
        }

        List<Map<String, Object>> parameters = new ArrayList<>();
        Parameter[] params = func.getParameters();
        for (int i = 0; i < params.length; i++) {
            Parameter param = params[i];
            Map<String, Object> paramInfo = new LinkedHashMap<>();
            paramInfo.put("name", param.getName());
            paramInfo.put("dataType", param.getDataType().getName());
            paramInfo.put("ordinal", i);
            String storage = param.getRegister() != null ? param.getRegister().getName() : "stack";
            paramInfo.put("storage", storage);
            parameters.add(paramInfo);
        }
        result.put("parameters", parameters);

        result.put("isExternal", func.isExternal());

        if (func.getCallingConventionName() != null) {
            result.put("callingConvention", func.getCallingConventionName());
        }

        if (func.getParentNamespace() != null) {
            result.put("namespace", func.getParentNamespace().getName());
        }

        return result;
    }
    
    private void handleDecompileFunction(HttpExchange exchange, String addrStr) throws Exception {
        String requestId = getRequestId(exchange);
        Address addr = parseAddressString(addrStr);
        Function func = program.getFunctionManager().getFunctionContaining(addr);
        
        if (func == null) {
            sendError(exchange, 404, "Function not found: " + addrStr, "FUNCTION_NOT_FOUND");
            return;
        }
        
        DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
        if (results == null || !results.decompileCompleted()) {
            sendError(exchange, 500, "Decompilation failed or timed out");
            return;
        }
                DecompiledFunction decompiledFunc = results.getDecompiledFunction();
        if (decompiledFunc == null) {
            sendError(exchange, 500, "Decompilation returned null");
            return;
        }
        
        String decompiledCode = decompiledFunc.getC();
        
        // Build result matching GUI format exactly
        Map<String, Object> functionInfo = new HashMap<>();
        functionInfo.put("address", func.getEntryPoint().toString());
        functionInfo.put("name", func.getName());
        
        Map<String, Object> result = new HashMap<>();
        result.put("decompiled", decompiledCode);  // Changed from "code" to "decompiled"
        result.put("function", functionInfo);      // Nested function object
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        // Normalize address (remove 0x prefix if present for consistency with GUI)
        String normalizedAddr = addrStr.startsWith("0x") ? addrStr.substring(2) : addrStr;
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/functions/" + normalizedAddr + "/decompile");
        links.put("function", "/functions/" + normalizedAddr);
        links.put("disassembly", "/functions/" + normalizedAddr + "/disassembly");
        links.put("variables", "/functions/" + normalizedAddr + "/variables");
        links.put("program", "/program");
        
        addLinks(response, links);
        sendJsonResponse(exchange, response, 200);
    }

    private void handleFunctionDisassembly(HttpExchange exchange, String addrStr) throws Exception {
        String requestId = getRequestId(exchange);
        Program currentProgram = getCurrentProgram();
        if (currentProgram == null) {
            sendError(exchange, 503, "No program is currently loaded", "NO_PROGRAM_LOADED");
            return;
        }

        Address addr = parseAddressString(addrStr);
        Function function = currentProgram.getFunctionManager().getFunctionContaining(addr);
        if (function == null) {
            sendError(exchange, 404, "Function not found at " + addrStr, "FUNCTION_NOT_FOUND");
            return;
        }

        List<Map<String, Object>> disassembly = new ArrayList<>();
        try {
            Address startAddr = function.getEntryPoint();
            Address endAddr = function.getBody().getMaxAddress();
            Listing listing = currentProgram.getListing();
            InstructionIterator iterator = listing.getInstructions(startAddr, true);

            while (iterator.hasNext() && disassembly.size() < 100) {
                Instruction instruction = iterator.next();
                if (instruction.getAddress().compareTo(endAddr) > 0) {
                    break;
                }

                Map<String, Object> instructionMap = new LinkedHashMap<>();
                instructionMap.put("address", instruction.getAddress().toString());

                byte[] bytes = new byte[instruction.getLength()];
                try {
                    currentProgram.getMemory().getBytes(instruction.getAddress(), bytes);
                } catch (MemoryAccessException e) {
                    Arrays.fill(bytes, (byte) 0x00);
                }
                StringBuilder hexBytes = new StringBuilder();
                for (byte b : bytes) {
                    hexBytes.append(String.format("%02X", b & 0xFF));
                }
                instructionMap.put("bytes", hexBytes.toString());

                String mnemonic = instruction.getMnemonicString();
                instructionMap.put("mnemonic", mnemonic);

                String fullInstruction = instruction.toString();
                String operands = fullInstruction.length() > mnemonic.length()
                    ? fullInstruction.substring(mnemonic.length()).trim()
                    : "";
                instructionMap.put("operands", operands);

                disassembly.add(instructionMap);
            }
        } catch (Exception e) {
            println("Failed to build disassembly for " + addrStr + ": " + e.getMessage());
        }

        if (disassembly.isEmpty()) {
            Address placeholderAddr = function.getEntryPoint();
            for (int i = 0; i < 5; i++) {
                Map<String, Object> placeholder = new LinkedHashMap<>();
                placeholder.put("address", placeholderAddr.toString());
                placeholder.put("mnemonic", "???");
                placeholder.put("operands", "???");
                placeholder.put("bytes", "????");
                disassembly.add(placeholder);
                placeholderAddr = placeholderAddr.add(2);
            }
        }

        Map<String, Object> functionInfo = new LinkedHashMap<>();
        functionInfo.put("address", function.getEntryPoint().toString());
        functionInfo.put("name", function.getName());
        functionInfo.put("signature", function.getSignature().toString());

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("function", functionInfo);
        result.put("instructions", disassembly);

        String normalizedAddr = addrStr.startsWith("0x") || addrStr.startsWith("0X")
            ? addrStr.substring(2)
            : addrStr;

        HeadlessResponseBuilder builder = new HeadlessResponseBuilder(requestId)
            .success(true)
            .result(result)
            .addLink("self", "/functions/" + normalizedAddr + "/disassembly")
            .addLink("function", "/functions/" + normalizedAddr)
            .addLink("decompile", "/functions/" + normalizedAddr + "/decompile")
            .addLink("variables", "/functions/" + normalizedAddr + "/variables")
            .addLink("program", "/program");

        sendJsonResponse(exchange, builder.build(), 200);
    }

    private void handleUpdateFunction(HttpExchange exchange, String addrStr) throws Exception {
        String requestId = getRequestId(exchange);
        Program currentProgram = getCurrentProgram();
        if (currentProgram == null) {
            sendError(exchange, 400, "No program is currently loaded", "NO_PROGRAM_LOADED");
            return;
        }

        Address addr = parseAddressString(addrStr);
        Function func = currentProgram.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            sendError(exchange, 404, "Function not found at " + addrStr, "FUNCTION_NOT_FOUND");
            return;
        }

        JsonObject body;
        try {
            body = parseRequestJson(exchange);
        } catch (IllegalArgumentException e) {
            sendError(exchange, 400, "Invalid JSON body", "INVALID_JSON");
            return;
        }

        String newName = getOptionalString(body, "name");
        String newSignature = getOptionalString(body, "signature");
        String newComment = getOptionalString(body, "comment");

        boolean changed = false;

        if (newName != null && !newName.isEmpty() && !newName.equals(func.getName())) {
            if (!renameFunction(func, newName)) {
                sendError(exchange, 400, "Failed to rename function", "RENAME_FAILED");
                return;
            }
            changed = true;
        }

        if (newSignature != null && !newSignature.isEmpty()) {
            if (!updateFunctionSignature(func, newSignature)) {
                sendError(exchange, 400, "Failed to set function signature: invalid signature format", "SIGNATURE_FAILED");
                return;
            }
            changed = true;
        }

        if (newComment != null) {
            if (!updateFunctionComment(func, newComment)) {
                sendError(exchange, 400, "Failed to set function comment", "COMMENT_FAILED");
                return;
            }
            changed = true;
        }

        if (!changed) {
            sendError(exchange, 400, "No changes specified", "NO_CHANGES");
            return;
        }

        Map<String, Object> result = buildFunctionInfoMap(func);

        HeadlessResponseBuilder builder = new HeadlessResponseBuilder(requestId)
            .success(true)
            .result(result)
            .addLink("self", "/programs/current/functions/" + func.getEntryPoint().toString())
            .addLink("by_name", "/programs/current/functions/by-name/" + func.getName())
            .addLink("program", "/programs/current");

        sendJsonResponse(exchange, builder.build(), 200);
    }

    private void handleDeleteFunction(HttpExchange exchange, String addrStr) throws IOException {
        sendError(exchange, 501, "Function deletion not implemented", "NOT_IMPLEMENTED");
    }
    
    private void handleFunctionCalls(HttpExchange exchange, String addrStr) throws Exception {
        String requestId = getRequestId(exchange);
        Address addr = parseAddressString(addrStr);
        Function func = program.getFunctionManager().getFunctionContaining(addr);
        
        if (func == null) {
            sendError(exchange, 404, "No function at address " + addrStr);
            return;
        }
        
        List<Map<String, Object>> calls = new ArrayList<>();
        Set<Function> calledFunctions = func.getCalledFunctions(monitor);
        
        for (Function called : calledFunctions) {
            Map<String, Object> callData = new HashMap<>();
            callData.put("name", called.getName());
            callData.put("address", called.getEntryPoint().toString());
            callData.put("isExternal", called.isExternal());
            callData.put("isThunk", called.isThunk());
            calls.add(callData);
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("function", func.getName());
        result.put("address", func.getEntryPoint().toString());
        result.put("calls", calls);
        result.put("count", calls.size());
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/functions/" + addrStr + "/calls");
        links.put("function", "/functions/" + addrStr);
        links.put("callers", "/functions/" + addrStr + "/callers");
        
        addLinks(response, links);
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleFunctionCallers(HttpExchange exchange, String addrStr) throws Exception {
        String requestId = getRequestId(exchange);
        Address addr = parseAddressString(addrStr);
        Function func = program.getFunctionManager().getFunctionAt(addr);
        
        if (func == null) {
            sendError(exchange, 404, "Function not found at " + addrStr);
            return;
        }
        
        List<Map<String, Object>> callers = new ArrayList<>();
        Set<Function> callingFunctions = func.getCallingFunctions(monitor);
        
        for (Function caller : callingFunctions) {
            Map<String, Object> callerData = new HashMap<>();
            callerData.put("name", caller.getName());
            callerData.put("address", caller.getEntryPoint().toString());
            callers.add(callerData);
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("function", func.getName());
        result.put("address", func.getEntryPoint().toString());
        result.put("callers", callers);
        result.put("count", callers.size());
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/functions/" + addrStr + "/callers");
        links.put("function", "/functions/" + addrStr);
        links.put("calls", "/functions/" + addrStr + "/calls");
        
        addLinks(response, links);
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleFunctionVariables(HttpExchange exchange, String addrStr) throws Exception {
        String requestId = getRequestId(exchange);
        Address addr = parseAddressString(addrStr);
        Function func = program.getFunctionManager().getFunctionAt(addr);
        
        if (func == null) {
            sendError(exchange, 404, "Function not found at " + addrStr);
            return;
        }
        
        List<Map<String, Object>> variables = new ArrayList<>();
        Variable[] localVars = func.getLocalVariables();
        
        for (Variable var : localVars) {
            Map<String, Object> varData = new HashMap<>();
            varData.put("name", var.getName());
            varData.put("dataType", var.getDataType().getName());
            varData.put("length", var.getLength());
            varData.put("comment", var.getComment());
            variables.add(varData);
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("function", func.getName());
        result.put("address", func.getEntryPoint().toString());
        result.put("variables", variables);
        result.put("count", variables.size());
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/functions/" + addrStr + "/variables");
        links.put("function", "/functions/" + addrStr);
        links.put("parameters", "/functions/" + addrStr + "/parameters");
        
        addLinks(response, links);
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleFunctionParameters(HttpExchange exchange, String addrStr) throws Exception {
        String requestId = getRequestId(exchange);
        Address addr = parseAddressString(addrStr);
        Function func = program.getFunctionManager().getFunctionAt(addr);
        
        if (func == null) {
            sendError(exchange, 404, "Function not found at " + addrStr);
            return;
        }
        
        List<Map<String, Object>> parameters = new ArrayList<>();
        Parameter[] params = func.getParameters();
        
        for (Parameter param : params) {
            Map<String, Object> paramData = new HashMap<>();
            paramData.put("name", param.getName());
            paramData.put("dataType", param.getDataType().getName());
            paramData.put("ordinal", param.getOrdinal());
            paramData.put("length", param.getLength());
            paramData.put("comment", param.getComment());
            parameters.add(paramData);
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("function", func.getName());
        result.put("address", func.getEntryPoint().toString());
        result.put("parameters", parameters);
        result.put("count", parameters.size());
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/functions/" + addrStr + "/parameters");
        links.put("function", "/functions/" + addrStr);
        links.put("variables", "/functions/" + addrStr + "/variables");
        
        addLinks(response, links);
        addLinks(response, links);
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleThunkFunctions(HttpExchange exchange) throws IOException {
        String requestId = getRequestId(exchange);
        FunctionManager funcMgr = program.getFunctionManager();
        List<Map<String, Object>> thunks = new ArrayList<>();
        
        FunctionIterator iter = funcMgr.getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.isThunk()) {
                Map<String, Object> thunkData = new HashMap<>();
                thunkData.put("name", func.getName());
                thunkData.put("address", func.getEntryPoint().toString());
                Function thunkedFunc = func.getThunkedFunction(false);
                if (thunkedFunc != null) {
                    thunkData.put("thunkedFunction", thunkedFunc.getName());
                    thunkData.put("thunkedAddress", thunkedFunc.getEntryPoint().toString());
                }
                thunks.add(thunkData);
            }
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("thunks", thunks);
        result.put("count", thunks.size());
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/functions/thunks");
        links.put("functions", "/functions");
        links.put("program", "/program");
        
        addLinks(response, links);
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleExternalFunctions(HttpExchange exchange) throws IOException {
        String requestId = getRequestId(exchange);
        FunctionManager funcMgr = program.getFunctionManager();
        List<Map<String, Object>> externals = new ArrayList<>();
        
        FunctionIterator iter = funcMgr.getExternalFunctions();
        while (iter.hasNext()) {
            Function func = iter.next();
            Map<String, Object> extData = new HashMap<>();
            extData.put("name", func.getName());
            extData.put("address", func.getEntryPoint().toString());
            extData.put("signature", func.getPrototypeString(true, false));
            ExternalLocation extLoc = func.getExternalLocation();
            if (extLoc != null) {
                extData.put("library", extLoc.getLibraryName());
                extData.put("originalName", extLoc.getOriginalImportedName());
            }
            externals.add(extData);
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("externals", externals);
        result.put("count", externals.size());
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/functions/external");
        links.put("functions", "/functions");
        links.put("imports", "/symbols/imports");
        links.put("program", "/program");
        
        addLinks(response, links);
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleFunctionByName(HttpExchange exchange) throws IOException {
        String requestId = getRequestId(exchange);
        String path = exchange.getRequestURI().getPath();
        
        // Extract function name from path: /functions/by-name/{name}
        String functionName = path.substring("/functions/by-name/".length());
        if (functionName.isEmpty()) {
            sendError(exchange, 400, "Function name is required");
            return;
        }
        
        // URL decode the function name
        try {
            functionName = java.net.URLDecoder.decode(functionName, "UTF-8");
        } catch (Exception e) {
            sendError(exchange, 400, "Invalid function name encoding");
            return;
        }
        
        // Search for function by name
        FunctionManager funcMgr = program.getFunctionManager();
        SymbolTable symTable = program.getSymbolTable();
        
        // Get all symbols with this name
        List<Symbol> symbols = symTable.getSymbols(functionName, null);
        Function foundFunc = null;
        
        for (Symbol sym : symbols) {
            if (sym.getSymbolType() == SymbolType.FUNCTION) {
                foundFunc = funcMgr.getFunctionAt(sym.getAddress());
                if (foundFunc != null) {
                    break;
                }
            }
        }
        
        if (foundFunc == null) {
            sendError(exchange, 404, "Function not found: " + functionName);
            return;
        }
        
        // Build function info
        Map<String, Object> funcInfo = new HashMap<>();
        funcInfo.put("name", foundFunc.getName());
        funcInfo.put("address", foundFunc.getEntryPoint().toString());
        funcInfo.put("signature", foundFunc.getPrototypeString(true, false));
        funcInfo.put("comment", foundFunc.getComment());
        funcInfo.put("parameterCount", foundFunc.getParameterCount());
        funcInfo.put("localVariableCount", foundFunc.getLocalVariables().length);
        funcInfo.put("isThunk", foundFunc.isThunk());
        funcInfo.put("isExternal", foundFunc.isExternal());
        funcInfo.put("callingConvention", foundFunc.getCallingConventionName());
        
        Map<String, Object> response = buildHateoasResponse(true, funcInfo, requestId);
        
        String addr = foundFunc.getEntryPoint().toString();
        Map<String, String> links = new HashMap<>();
        links.put("self", "/functions/by-name/" + functionName);
        links.put("function", "/functions/" + addr);
        links.put("decompile", "/functions/" + addr + "/decompile");
        links.put("calls", "/functions/" + addr + "/calls");
        links.put("callers", "/functions/" + addr + "/callers");
        links.put("program", "/program");
        
        addLinks(response, links);
        sendJsonResponse(exchange, response, 200);
    }
    
    // ==================== STRING ENDPOINTS ====================
    private void registerStringEndpoints() {
        server.createContext("/strings", exchange -> {
            String query = exchange.getRequestURI().getQuery();
            handleListStrings(exchange, query);
        });
    }
    
    private void handleListStrings(HttpExchange exchange, String query) throws IOException {
        String requestId = getRequestId(exchange);
        Map<String, String> params = parseQuery(query);
        int page = Integer.parseInt(params.getOrDefault("page", "1"));
        int perPage = Integer.parseInt(params.getOrDefault("per_page", "50"));
        int minLength = Integer.parseInt(params.getOrDefault("min_length", "4"));
        
        List<Map<String, Object>> strings = new ArrayList<>();
        
        // Find all defined strings
        DataIterator dataIter = program.getListing().getDefinedData(true);
        int skip = (page - 1) * perPage;
        int count = 0;
        int total = 0;
        
        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            if (data.hasStringValue()) {
                total++;
                
                String value = data.getDefaultValueRepresentation();
                if (value.length() >= minLength) {
                    if (skip > 0) {
                        skip--;
                        continue;
                    }
                    
                    if (count < perPage) {
                        Map<String, Object> strData = new HashMap<>();
                        strData.put("address", data.getAddress().toString());
                        strData.put("value", value);
                        strData.put("length", value.length());
                        strData.put("type", data.getDataType().getName());
                        strings.add(strData);
                        count++;
                    }
                }
            }
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("strings", strings);
        result.put("total", total);
        result.put("page", page);
        result.put("per_page", perPage);
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/strings");
        links.put("program", "/program");
        links.put("memory", "/memory");
        addLinks(response, links);
        
        addPaginationLinks(response, "/strings", page, perPage, total);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    // ==================== SYMBOL ENDPOINTS ====================
    private void registerSymbolEndpoints() {
        server.createContext("/symbols/imports", this::handleSymbolImports);
        server.createContext("/symbols/exports", this::handleSymbolExports);
        server.createContext("/symbols", exchange -> {
            String query = exchange.getRequestURI().getQuery();
            handleListSymbols(exchange, query);
        });
    }
    
    private void handleListSymbols(HttpExchange exchange, String query) throws IOException {
        String requestId = getRequestId(exchange);
        Map<String, String> params = parseQuery(query);
        int page = Integer.parseInt(params.getOrDefault("page", "1"));
        int perPage = Integer.parseInt(params.getOrDefault("per_page", "50"));
        String filter = params.getOrDefault("filter", "");
        
        SymbolTable symTable = program.getSymbolTable();
        List<Map<String, Object>> symbols = new ArrayList<>();
        
        SymbolIterator iter = symTable.getAllSymbols(true);
        int skip = (page - 1) * perPage;
        int count = 0;
        int total = 0;
        
        // Count total first for pagination
        SymbolIterator countIter = symTable.getAllSymbols(true);
        while (countIter.hasNext()) {
            Symbol sym = countIter.next();
            if (filter.isEmpty() || sym.getName().contains(filter)) {
                total++;
            }
        }
        
        while (iter.hasNext() && count < perPage) {
            Symbol sym = iter.next();
            
            // Skip if filter doesn't match
            if (!filter.isEmpty() && !sym.getName().contains(filter)) {
                continue;
            }
            
            if (skip > 0) {
                skip--;
                continue;
            }
            
            Map<String, Object> symData = new HashMap<>();
            symData.put("name", sym.getName());
            symData.put("address", sym.getAddress().toString());
            symData.put("type", sym.getSymbolType().toString());
            symData.put("source", sym.getSource().toString());
            symData.put("isPrimary", sym.isPrimary());
            symData.put("isGlobal", sym.isGlobal());
            symbols.add(symData);
            count++;
        }
        
        Map<String, Object> response = buildHateoasResponse(true, symbols, requestId);
        
        // Add metadata
        response.put("total", total);
        response.put("page", page);
        response.put("per_page", perPage);
        if (!filter.isEmpty()) {
            response.put("filter", filter);
        }
        
        // Add pagination links
        addPaginationLinks(response, "/symbols", page, perPage, total);
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleSymbolImports(HttpExchange exchange) throws IOException {
        String requestId = getRequestId(exchange);
        Map<String, String> params = parseQuery(exchange.getRequestURI().getQuery());
        int offset = Integer.parseInt(params.getOrDefault("offset", "0"));
        int limit = Integer.parseInt(params.getOrDefault("limit", "100"));
        
        SymbolTable symTable = program.getSymbolTable();
        List<Map<String, Object>> allImports = new ArrayList<>();
        
        // Get all external symbols (imports)
        SymbolIterator iter = symTable.getExternalSymbols();
        while (iter.hasNext()) {
            Symbol sym = iter.next();
            Map<String, Object> imp = new HashMap<>();
            imp.put("name", sym.getName());
            imp.put("address", sym.getAddress().toString());
            imp.put("namespace", sym.getParentNamespace().getName());
            allImports.add(imp);
        }
        
        // Apply pagination
        int total = allImports.size();
        int fromIndex = Math.min(offset, total);
        int toIndex = Math.min(offset + limit, total);
        List<Map<String, Object>> paginatedImports = allImports.subList(fromIndex, toIndex);
        
        Map<String, Object> response = buildHateoasResponse(true, paginatedImports, requestId);
        
        // Add pagination info
        response.put("total", total);
        response.put("offset", offset);
        response.put("limit", limit);
        
        // Add links
        Map<String, String> links = new HashMap<>();
        links.put("self", "/symbols/imports?offset=" + offset + "&limit=" + limit);
        links.put("symbols", "/symbols");
        links.put("program", "/program");
        
        // Next/prev links
        if (offset + limit < total) {
            links.put("next", "/symbols/imports?offset=" + (offset + limit) + "&limit=" + limit);
        }
        if (offset > 0) {
            int prevOffset = Math.max(0, offset - limit);
            links.put("prev", "/symbols/imports?offset=" + prevOffset + "&limit=" + limit);
        }
        
        addLinks(response, links);
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleSymbolExports(HttpExchange exchange) throws IOException {
        String requestId = getRequestId(exchange);
        Map<String, String> params = parseQuery(exchange.getRequestURI().getQuery());
        int offset = Integer.parseInt(params.getOrDefault("offset", "0"));
        int limit = Integer.parseInt(params.getOrDefault("limit", "100"));
        
        SymbolTable symTable = program.getSymbolTable();
        List<Map<String, Object>> allExports = new ArrayList<>();
        
        // Get all export entry points
        SymbolIterator iter = symTable.getAllSymbols(true);
        while (iter.hasNext()) {
            Symbol sym = iter.next();
            if (sym.isExternalEntryPoint()) {
                Map<String, Object> exp = new HashMap<>();
                exp.put("name", sym.getName());
                exp.put("address", sym.getAddress().toString());
                exp.put("namespace", sym.getParentNamespace().getName());
                allExports.add(exp);
            }
        }
        
        // Apply pagination
        int total = allExports.size();
        int fromIndex = Math.min(offset, total);
        int toIndex = Math.min(offset + limit, total);
        List<Map<String, Object>> paginatedExports = allExports.subList(fromIndex, toIndex);
        
        Map<String, Object> response = buildHateoasResponse(true, paginatedExports, requestId);
        
        // Add pagination info
        response.put("total", total);
        response.put("offset", offset);
        response.put("limit", limit);
        
        // Add links
        Map<String, String> links = new HashMap<>();
        links.put("self", "/symbols/exports?offset=" + offset + "&limit=" + limit);
        links.put("symbols", "/symbols");
        links.put("program", "/program");
        
        // Next/prev links
        if (offset + limit < total) {
            links.put("next", "/symbols/exports?offset=" + (offset + limit) + "&limit=" + limit);
        }
        if (offset > 0) {
            int prevOffset = Math.max(0, offset - limit);
            links.put("prev", "/symbols/exports?offset=" + prevOffset + "&limit=" + limit);
        }
        
        addLinks(response, links);
        sendJsonResponse(exchange, response, 200);
    }
    
    // ==================== MEMORY ENDPOINTS ====================
    private void registerMemoryEndpoints() {
        server.createContext("/memory", exchange -> {
            safeHandle(exchange, ex -> {
                String path = ex.getRequestURI().getPath();
                String query = ex.getRequestURI().getQuery();
                
                String[] segments = path.split("/");
                
                if (segments.length == 2 || (segments.length == 3 && segments[2].isEmpty())) {
                    // /memory or /memory/ - check query params to determine action
                    if (query != null && query.contains("address")) {
                        // Has address parameter - this is a read request
                        handleMemoryRead(ex, query);
                    } else if (query != null && query.contains("pattern")) {
                        // Has pattern parameter - this is a search request
                        handleMemorySearch(ex, query);
                    } else {
                        // No specific parameters - return memory info
                        handleMemoryInfo(ex);
                    }
                } else if (segments.length == 3) {
                    String action = segments[2];
                    switch (action) {
                        case "read":
                            handleMemoryRead(ex, query);
                            break;
                        case "search":
                            handleMemorySearch(ex, query);
                            break;
                        case "strings":
                            handleMemoryStrings(ex, query);
                            break;
                        case "blocks":
                            // GUI-compatible memory blocks endpoint
                            handleMemoryBlocks(ex, query);
                            break;
                        default:
                            // Check if this is an address with sub-resources
                            // Format: /memory/{address}/comments/{type}
                            if (segments.length >= 5 && segments[3].equals("comments")) {
                                String addressStr = segments[2];
                                String commentType = segments[4];
                                handleMemoryComments(ex, addressStr, commentType);
                            } else {
                                sendError(ex, 404, "Unknown memory action: " + action);
                            }
                    }
                } else if (segments.length >= 5 && segments[3].equals("comments")) {
                    // Handle /memory/{address}/comments/{type}
                    String addressStr = segments[2];
                    String commentType = segments[4];
                    handleMemoryComments(ex, addressStr, commentType);
                } else {
                    sendError(ex, 404, "Invalid memory endpoint path");
                }
            });
        });
    }
    
    private void handleMemoryInfo(HttpExchange exchange) throws IOException {
        String requestId = getRequestId(exchange);
        Memory memory = program.getMemory();
        
        List<Map<String, Object>> blocks = new ArrayList<>();
        for (MemoryBlock block : memory.getBlocks()) {
            Map<String, Object> blockData = new HashMap<>();
            blockData.put("name", block.getName());
            blockData.put("start", block.getStart().toString());
            blockData.put("end", block.getEnd().toString());
            blockData.put("size", block.getSize());
            blockData.put("isExecute", block.isExecute());
            blockData.put("isWrite", block.isWrite());
            blockData.put("isRead", block.isRead());
            blockData.put("isInitialized", block.isInitialized());
            blocks.add(blockData);
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("blocks", blocks);
        result.put("totalSize", memory.getSize());
        result.put("numBlocks", blocks.size());
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/memory");
        links.put("read", "/memory/read");
        links.put("search", "/memory/search");
        links.put("strings", "/memory/strings");
        links.put("program", "/program");
        
        addLinks(response, links);
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleMemoryRead(HttpExchange exchange, String query) throws Exception {
        String requestId = getRequestId(exchange);
        Map<String, String> params = parseQuery(query);
        String addrStr = params.get("address");
        String startStr = params.get("start_address");
        String endStr = params.get("end_address");
        String format = params.getOrDefault("format", "hex");
        int length = Integer.parseInt(params.getOrDefault("length", "256"));
        
        if (addrStr == null && startStr == null) {
            sendError(exchange, 400, "Missing address or start_address parameter");
            return;
        }
        
        byte[] bytes;
        Address startAddr;
        boolean truncated = false;
        
        if (startStr != null && endStr != null) {
            // Range read (start_address to end_address)
            startAddr = parseAddressString(startStr);
            Address endAddr = parseAddressString(endStr);
            long rangeSize = endAddr.subtract(startAddr) + 1;
            
            // Safety limit for range reads: 1MB
            if (rangeSize > 1024 * 1024) {
                rangeSize = 1024 * 1024;
                truncated = true;
            }
            
            bytes = new byte[(int)rangeSize];
            program.getMemory().getBytes(startAddr, bytes);
        } else {
            // Single address read
            startAddr = parseAddressString(addrStr != null ? addrStr : startStr);
            
            // Safety limit for single address: 64KB
            int readLength = Math.min(length, 65536);
            bytes = new byte[readLength];
            program.getMemory().getBytes(startAddr, bytes);
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("address", startAddr.toString());
        result.put("bytesRead", bytes.length);  // Changed from "length" to match GUI
        
        // Always provide both rawBytes (base64) and hexBytes - like GUI does
        result.put("rawBytes", Base64.getEncoder().encodeToString(bytes));
        
        // Build hex string with uppercase and spaces to match GUI format
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) {
                hex.append(" ");
            }
            hex.append(String.format("%02X", bytes[i] & 0xFF));
        }
        result.put("hexBytes", hex.toString());
        
        if (truncated) {
            result.put("truncated", true);
        }
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        // Build self link with actual query parameters
        StringBuilder selfLink = new StringBuilder("/memory?address=").append(startAddr.toString());
        if (params.containsKey("length")) {
            selfLink.append("&length=").append(length);
        }
        if (params.containsKey("format")) {
            selfLink.append("&format=").append(format);
        }
        
        Map<String, String> links = new HashMap<>();
        links.put("self", selfLink.toString());
        links.put("program", "/program");
        links.put("blocks", "/memory/blocks");
        
        // Add prev/next links for navigation
        try {
            long addrValue = Long.parseLong(startAddr.toString(), 16);
            Address nextAddr = startAddr.add(bytes.length);
            links.put("next", "/memory?address=" + nextAddr.toString() + "&length=" + length);
            
            if (addrValue >= length) {
                Address prevAddr = startAddr.subtract(length);
                links.put("prev", "/memory?address=" + prevAddr.toString() + "&length=" + length);
            }
        } catch (Exception e) {
            // If we can't calculate next/prev, just skip them
        }
        
        addLinks(response, links);
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleMemorySearch(HttpExchange exchange, String query) throws IOException {
        String requestId = getRequestId(exchange);
        Map<String, String> params = parseQuery(query);
        String pattern = params.get("pattern");
        
        if (pattern == null) {
            sendError(exchange, 400, "Missing pattern parameter");
            return;
        }
        
        // Convert hex pattern to bytes
        byte[] searchBytes;
        try {
            searchBytes = hexStringToByteArray(pattern);
        } catch (Exception e) {
            sendError(exchange, 400, "Invalid hex pattern");
            return;
        }
        
        List<Map<String, Object>> matches = new ArrayList<>();
        Memory memory = program.getMemory();
        
        // Search in all memory blocks
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized()) continue;
            
            Address searchAddr = block.getStart();
            while (searchAddr != null && searchAddr.compareTo(block.getEnd()) <= 0) {
                Address found = memory.findBytes(searchAddr, block.getEnd(), searchBytes, null, true, null);
                if (found == null) break;
                
                Map<String, Object> match = new HashMap<>();
                match.put("address", found.toString());
                match.put("block", block.getName());
                matches.add(match);
                
                searchAddr = found.add(1);
                if (matches.size() >= 100) break; // Limit results
            }
            if (matches.size() >= 100) break;
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("matches", matches);
        result.put("count", matches.size());
        result.put("pattern", pattern);
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/memory/search?pattern=" + pattern);
        links.put("memory", "/memory");
        
        addLinks(response, links);
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleMemoryStrings(HttpExchange exchange, String query) throws IOException {
        String requestId = getRequestId(exchange);
        Map<String, String> params = parseQuery(query);
        int minLength = Integer.parseInt(params.getOrDefault("min_length", "4"));
        
        List<Map<String, Object>> strings = new ArrayList<>();
        DataIterator dataIter = program.getListing().getDefinedData(true);
        
        int count = 0;
        while (dataIter.hasNext() && count < 100) {
            Data data = dataIter.next();
            if (data.hasStringValue()) {
                String value = data.getDefaultValueRepresentation();
                if (value.length() >= minLength) {
                    Map<String, Object> strData = new HashMap<>();
                    strData.put("address", data.getAddress().toString());
                    strData.put("value", value);
                    strData.put("length", value.length());
                    strings.add(strData);
                    count++;
                }
            }
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("strings", strings);
        result.put("count", strings.size());
        result.put("minLength", minLength);
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/memory/strings?min_length=" + minLength);
        links.put("memory", "/memory");
        links.put("allStrings", "/strings");
        
        addLinks(response, links);
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleMemoryBlocks(HttpExchange exchange, String query) throws IOException {
        String requestId = getRequestId(exchange);
        Map<String, String> params = parseQuery(query);
        int offset = Integer.parseInt(params.getOrDefault("offset", "0"));
        int limit = Integer.parseInt(params.getOrDefault("limit", "100"));
        
        Memory memory = program.getMemory();
        List<Map<String, Object>> allBlocks = new ArrayList<>();
        
        // Collect all memory blocks
        for (MemoryBlock block : memory.getBlocks()) {
            Map<String, Object> blockInfo = new HashMap<>();
            blockInfo.put("name", block.getName());
            blockInfo.put("start", block.getStart().toString());
            blockInfo.put("end", block.getEnd().toString());
            blockInfo.put("size", block.getSize());
            
            // Build permissions string matching GUI format: "rwxv"
            StringBuilder perms = new StringBuilder();
            perms.append(block.isRead() ? "r" : "-");
            perms.append(block.isWrite() ? "w" : "-");
            perms.append(block.isExecute() ? "x" : "-");
            perms.append(block.isVolatile() ? "v" : "-");
            blockInfo.put("permissions", perms.toString());
            
            // GUI fields
            blockInfo.put("isInitialized", block.isInitialized());
            blockInfo.put("isLoaded", block.isLoaded());
            blockInfo.put("isMapped", block.isMapped());
            
            allBlocks.add(blockInfo);
        }
        
        // Apply pagination
        int total = allBlocks.size();
        int fromIndex = Math.min(offset, total);
        int toIndex = Math.min(offset + limit, total);
        List<Map<String, Object>> paginatedBlocks = allBlocks.subList(fromIndex, toIndex);
        
        Map<String, Object> response = buildHateoasResponse(true, paginatedBlocks, requestId);
        
        // Add pagination metadata
        response.put("total", total);
        response.put("offset", offset);
        response.put("limit", limit);
        
        // Add HATEOAS links
        Map<String, String> links = new HashMap<>();
        links.put("self", "/memory/blocks" + (query != null && !query.isEmpty() ? "?" + query : ""));
        links.put("program", "/program");
        links.put("memory", "/memory");
        
        // Add next/prev links for pagination
        if (toIndex < total) {
            links.put("next", "/memory/blocks?offset=" + toIndex + "&limit=" + limit);
        }
        if (offset > 0) {
            int prevOffset = Math.max(0, offset - limit);
            links.put("prev", "/memory/blocks?offset=" + prevOffset + "&limit=" + limit);
        }
        
        addLinks(response, links);
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleMemoryComments(HttpExchange exchange, String addressStr, String commentType) throws IOException {
        String requestId = getRequestId(exchange);
        String method = exchange.getRequestMethod();
        
        // Validate comment type
        if (!isValidCommentType(commentType)) {
            Map<String, Object> error = new HashMap<>();
            error.put("id", requestId);
            error.put("instance", "http://localhost:" + port);
            error.put("success", false);
            error.put("error", "Invalid comment type: " + commentType);
            error.put("error_code", "INVALID_COMMENT_TYPE");
            sendJsonResponse(exchange, error, 400);
            return;
        }
        
        // Parse address
        AddressFactory addressFactory = program.getAddressFactory();
        Address address;
        try {
            address = addressFactory.getAddress(addressStr);
        } catch (Exception e) {
            Map<String, Object> error = new HashMap<>();
            error.put("id", requestId);
            error.put("instance", "http://localhost:" + port);
            error.put("success", false);
            error.put("error", "Invalid address format: " + addressStr);
            error.put("error_code", "INVALID_ADDRESS");
            sendJsonResponse(exchange, error, 400);
            return;
        }
        
        if ("GET".equals(method)) {
            // Get existing comment
            String comment = getCommentByType(address, commentType);
            
            Map<String, Object> result = new HashMap<>();
            result.put("address", addressStr);
            result.put("comment_type", commentType);
            result.put("comment", comment != null ? comment : "");
            
            Map<String, Object> response = buildHateoasResponse(true, result, requestId);
            
            Map<String, String> links = new HashMap<>();
            links.put("self", "/memory/" + addressStr + "/comments/" + commentType);
            links.put("memory", "/memory");
            links.put("program", "/program");
            
            addLinks(response, links);
            sendJsonResponse(exchange, response, 200);
            
        } else if ("POST".equals(method)) {
            // Set comment - read JSON body
            String requestBody;
            try {
                InputStream is = exchange.getRequestBody();
                requestBody = new String(is.readAllBytes(), "UTF-8");
            } catch (Exception e) {
                Map<String, Object> error = new HashMap<>();
                error.put("id", requestId);
                error.put("instance", "http://localhost:" + port);
                error.put("success", false);
                error.put("error", "Failed to read request body");
                error.put("error_code", "INVALID_REQUEST");
                sendJsonResponse(exchange, error, 400);
                return;
            }
            
            // Simple JSON parsing for {"comment": "value"}
            String comment = null;
            try {
                // Extract comment value from JSON
                int commentIdx = requestBody.indexOf("\"comment\"");
                if (commentIdx != -1) {
                    int colonIdx = requestBody.indexOf(":", commentIdx);
                    if (colonIdx != -1) {
                        int valueStart = requestBody.indexOf("\"", colonIdx) + 1;
                        int valueEnd = requestBody.indexOf("\"", valueStart);
                        if (valueStart > 0 && valueEnd > valueStart) {
                            comment = requestBody.substring(valueStart, valueEnd);
                            // Unescape JSON string
                            comment = comment.replace("\\\"", "\"")
                                           .replace("\\\\", "\\")
                                           .replace("\\n", "\n")
                                           .replace("\\r", "\r")
                                           .replace("\\t", "\t");
                        }
                    }
                }
            } catch (Exception e) {
                // Ignore parsing errors, comment will be null
            }
            
            if (comment == null) {
                Map<String, Object> error = new HashMap<>();
                error.put("id", requestId);
                error.put("instance", "http://localhost:" + port);
                error.put("success", false);
                error.put("error", "Comment parameter is required");
                error.put("error_code", "MISSING_PARAMETER");
                sendJsonResponse(exchange, error, 400);
                return;
            }
            
            boolean success = setCommentByType(address, commentType, comment);
            
            if (success) {
                Map<String, Object> result = new HashMap<>();
                result.put("address", addressStr);
                result.put("comment_type", commentType);
                result.put("comment", comment);
                
                Map<String, Object> response = buildHateoasResponse(true, result, requestId);
                
                Map<String, String> links = new HashMap<>();
                links.put("self", "/memory/" + addressStr + "/comments/" + commentType);
                links.put("memory", "/memory");
                links.put("program", "/program");
                
                addLinks(response, links);
                sendJsonResponse(exchange, response, 200);
            } else {
                Map<String, Object> error = new HashMap<>();
                error.put("id", requestId);
                error.put("instance", "http://localhost:" + port);
                error.put("success", false);
                error.put("error", "Failed to set comment");
                error.put("error_code", "COMMENT_SET_FAILED");
                sendJsonResponse(exchange, error, 500);
            }
        } else {
            Map<String, Object> error = new HashMap<>();
            error.put("id", requestId);
            error.put("instance", "http://localhost:" + port);
            error.put("success", false);
            error.put("error", "Method Not Allowed");
            error.put("error_code", "METHOD_NOT_ALLOWED");
            sendJsonResponse(exchange, error, 405);
        }
    }
    
    /**
     * Check if the comment type is valid
     */
    private boolean isValidCommentType(String commentType) {
        return commentType.equals("plate") || 
               commentType.equals("pre") || 
               commentType.equals("post") || 
               commentType.equals("eol") ||
               commentType.equals("repeatable");
    }
    
    /**
     * Get a comment by type at the specified address
     */
    private String getCommentByType(Address address, String commentType) {
        int type = getCommentTypeInt(commentType);
        return program.getListing().getComment(type, address);
    }
    
    /**
     * Set a comment by type at the specified address
     */
    private boolean setCommentByType(Address address, String commentType, String comment) {
        int type = getCommentTypeInt(commentType);
        
        int transactionID = program.startTransaction("Set Comment");
        boolean success = false;
        try {
            program.getListing().setComment(address, type, comment);
            success = true;
        } catch (Exception e) {
            println("Error setting comment: " + e.getMessage());
        } finally {
            program.endTransaction(transactionID, success);
        }
        
        return success;
    }
    
    /**
     * Convert comment type string to Ghidra's internal comment type constants
     */
    private int getCommentTypeInt(String commentType) {
        switch (commentType.toLowerCase()) {
            case "plate":
                return CodeUnit.PLATE_COMMENT;
            case "pre":
                return CodeUnit.PRE_COMMENT;
            case "post":
                return CodeUnit.POST_COMMENT;
            case "eol":
                return CodeUnit.EOL_COMMENT;
            case "repeatable":
                return CodeUnit.REPEATABLE_COMMENT;
            default:
                return CodeUnit.PLATE_COMMENT;
        }
    }
    
    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    
    // ==================== XREF ENDPOINTS ====================
    private void registerXrefEndpoints() {
        server.createContext("/xrefs", exchange -> {
            safeHandle(exchange, ex -> {
                String query = ex.getRequestURI().getQuery();
                handleGetXrefs(ex, query);
            });
        });
    }
    
    private void handleGetXrefs(HttpExchange exchange, String query) throws Exception {
        String requestId = getRequestId(exchange);
        Map<String, String> params = parseQuery(query);

        String toAddrStr = params.get("to_addr");
        String fromAddrStr = params.get("from_addr");
        String typeFilter = params.get("type");
        int offset = parseIntOrDefault(params.get("offset"), 0);
        int limit = parseIntOrDefault(params.get("limit"), 50);

        Program currentProgram = getCurrentProgram();
        if (currentProgram == null) {
            sendError(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
            return;
        }

        if ((toAddrStr == null || toAddrStr.isEmpty()) && (fromAddrStr == null || fromAddrStr.isEmpty())) {
            sendError(exchange, 400, "Either to_addr or from_addr parameter is required", "MISSING_PARAMETER");
            return;
        }

        offset = Math.max(0, offset);
        limit = Math.max(1, limit);

        Address toAddr = null;
        Address fromAddr = null;

        if (toAddrStr != null && !toAddrStr.isEmpty()) {
            try {
                toAddr = parseAddressString(toAddrStr);
            } catch (Exception e) {
                sendError(exchange, 400, "Invalid to_addr format: " + toAddrStr, "INVALID_PARAMETER");
                return;
            }
        }

        if (fromAddrStr != null && !fromAddrStr.isEmpty()) {
            try {
                fromAddr = parseAddressString(fromAddrStr);
            } catch (Exception e) {
                sendError(exchange, 400, "Invalid from_addr format: " + fromAddrStr, "INVALID_PARAMETER");
                return;
            }
        }

        if (typeFilter != null && typeFilter.isEmpty()) {
            typeFilter = null;
        }

        ReferenceManager refManager = currentProgram.getReferenceManager();
        List<Map<String, Object>> references = new ArrayList<>();

        if (toAddr != null) {
            ReferenceIterator refsToIter = refManager.getReferencesTo(toAddr);
            while (refsToIter.hasNext()) {
                Reference ref = refsToIter.next();
                if (!matchesReferenceType(ref, typeFilter)) {
                    continue;
                }
                references.add(createReferenceMap(currentProgram, ref, "to"));
            }
        }

        if (fromAddr != null) {
            Reference[] refsFrom = refManager.getReferencesFrom(fromAddr);
            for (Reference ref : refsFrom) {
                if (!matchesReferenceType(ref, typeFilter)) {
                    continue;
                }
                references.add(createReferenceMap(currentProgram, ref, "from"));
            }
        }

        references.sort((a, b) -> {
            int directionCompare = ((String) a.get("direction")).compareTo((String) b.get("direction"));
            if (directionCompare != 0) {
                return directionCompare;
            }

            int typeCompare = ((String) a.get("refType")).compareTo((String) b.get("refType"));
            if (typeCompare != 0) {
                return typeCompare;
            }

            return ((String) a.get("from_addr")).compareTo((String) b.get("from_addr"));
        });

        int total = references.size();
        int endIndex = Math.min(total, offset + limit);
        List<Map<String, Object>> paginatedReferences = offset < total
            ? new ArrayList<>(references.subList(offset, endIndex))
            : Collections.emptyList();

        Map<String, Object> result = new LinkedHashMap<>();
        if (toAddrStr != null && !toAddrStr.isEmpty()) {
            result.put("to_addr", toAddrStr);
        }
        if (fromAddrStr != null && !fromAddrStr.isEmpty()) {
            result.put("from_addr", fromAddrStr);
        }
        result.put("references", paginatedReferences);

        HeadlessResponseBuilder builder = new HeadlessResponseBuilder(requestId)
            .success(true)
            .metadata("size", total)
            .metadata("offset", offset)
            .metadata("limit", limit)
            .result(result)
            .addLink("program", "/program");

        String queryBase = buildXrefQueryString(toAddrStr, fromAddrStr, typeFilter);
        String queryPrefix = queryBase.isEmpty() ? "" : queryBase + "&";

        builder.addLink("self", "/xrefs?" + queryPrefix + "offset=" + offset + "&limit=" + limit);

        if (offset > 0) {
            int prevOffset = Math.max(0, offset - limit);
            builder.addLink("prev", "/xrefs?" + queryPrefix + "offset=" + prevOffset + "&limit=" + limit);
        }

        if (offset + limit < total) {
            builder.addLink("next", "/xrefs?" + queryPrefix + "offset=" + (offset + limit) + "&limit=" + limit);
        }

        if (toAddrStr != null && !toAddrStr.isEmpty()) {
            builder.addLink("to_function", "/functions/" + toAddrStr);
        }
        if (fromAddrStr != null && !fromAddrStr.isEmpty()) {
            builder.addLink("from_function", "/functions/" + fromAddrStr);
        }

        sendJsonResponse(exchange, builder.build(), 200);
    }

    private boolean matchesReferenceType(Reference reference, String typeFilter) {
        if (typeFilter == null) {
            return true;
        }
        return reference.getReferenceType().getName().equalsIgnoreCase(typeFilter);
    }

    private Map<String, Object> createReferenceMap(Program currentProgram, Reference ref, String direction) {
        Map<String, Object> refMap = new LinkedHashMap<>();
        refMap.put("direction", direction);
        refMap.put("from_addr", ref.getFromAddress().toString());
        refMap.put("to_addr", ref.getToAddress().toString());
        refMap.put("refType", ref.getReferenceType().getName());
        refMap.put("isPrimary", ref.isPrimary());

        Function fromFunction = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
        if (fromFunction != null) {
            Map<String, Object> fromFuncMap = new LinkedHashMap<>();
            fromFuncMap.put("name", fromFunction.getName());
            fromFuncMap.put("address", fromFunction.getEntryPoint().toString());
            fromFuncMap.put("offset", ref.getFromAddress().subtract(fromFunction.getEntryPoint()));
            refMap.put("from_function", fromFuncMap);
        }

        Function toFunction = currentProgram.getFunctionManager().getFunctionContaining(ref.getToAddress());
        if (toFunction != null) {
            Map<String, Object> toFuncMap = new LinkedHashMap<>();
            toFuncMap.put("name", toFunction.getName());
            toFuncMap.put("address", toFunction.getEntryPoint().toString());
            toFuncMap.put("offset", ref.getToAddress().subtract(toFunction.getEntryPoint()));
            refMap.put("to_function", toFuncMap);
        }

        SymbolTable symbolTable = currentProgram.getSymbolTable();
        Symbol[] fromSymbols = symbolTable.getSymbols(ref.getFromAddress());
        if (fromSymbols != null && fromSymbols.length > 0) {
            refMap.put("from_symbol", fromSymbols[0].getName());
        }

        Symbol[] toSymbols = symbolTable.getSymbols(ref.getToAddress());
        if (toSymbols != null && toSymbols.length > 0) {
            refMap.put("to_symbol", toSymbols[0].getName());
        }

        try {
            CodeUnit fromCodeUnit = currentProgram.getListing().getCodeUnitAt(ref.getFromAddress());
            if (fromCodeUnit != null) {
                refMap.put("from_instruction", fromCodeUnit.toString());
            }
        } catch (Exception e) {
            // Ignore failures retrieving code unit
        }

        try {
            CodeUnit toCodeUnit = currentProgram.getListing().getCodeUnitAt(ref.getToAddress());
            if (toCodeUnit != null) {
                refMap.put("to_instruction", toCodeUnit.toString());
            }
        } catch (Exception e) {
            // Ignore failures retrieving code unit
        }

        return refMap;
    }

    private String buildXrefQueryString(String toAddr, String fromAddr, String typeFilter) {
        StringBuilder builder = new StringBuilder();

        if (toAddr != null && !toAddr.isEmpty()) {
            builder.append("to_addr=").append(toAddr);
        }

        if (fromAddr != null && !fromAddr.isEmpty()) {
            if (builder.length() > 0) {
                builder.append("&");
            }
            builder.append("from_addr=").append(fromAddr);
        }

        if (typeFilter != null && !typeFilter.isEmpty()) {
            if (builder.length() > 0) {
                builder.append("&");
            }
            builder.append("type=").append(typeFilter);
        }

        return builder.toString();
    }
    
    // ==================== Additional Endpoint Stubs ====================
    // Note: registerAnalysisEndpoints() and registerClassEndpoints() are defined below
    
    private void registerDataEndpoints() {
        server.createContext("/data", exchange -> {
            safeHandle(exchange, ex -> {
                String method = ex.getRequestMethod();
                String path = ex.getRequestURI().getPath();
                String query = ex.getRequestURI().getQuery();
                
                if (!method.equals("GET")) {
                    sendError(ex, 405, "Method not allowed");
                    return;
                }
                
                // Parse path segments: /data/[address]/[action]
                String[] segments = path.split("/");
                
                if (segments.length == 2 || (segments.length == 3 && segments[2].isEmpty())) {
                    // /data or /data/
                    handleListData(ex, query);
                } else if (segments.length == 3) {
                    // /data/{address}
                    handleGetDataAt(ex, segments[2]);
                } else if (segments.length == 4 && segments[3].equals("references")) {
                    // /data/{address}/references
                    handleDataReferences(ex, segments[2]);
                } else {
                    sendError(ex, 404, "Invalid data endpoint path");
                }
            });
        });
    }
    
    private void handleListData(HttpExchange exchange, String query) throws IOException {
        String requestId = getRequestId(exchange);
        Map<String, String> params = parseQuery(query);
        int page = Integer.parseInt(params.getOrDefault("page", "1"));
        int perPage = Integer.parseInt(params.getOrDefault("per_page", "50"));
        
        List<Map<String, Object>> dataList = new ArrayList<>();
        DataIterator dataIter = program.getListing().getDefinedData(true);
        
        int skip = (page - 1) * perPage;
        int count = 0;
        int total = 0;
        
        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            total++;
            
            if (skip > 0) {
                skip--;
                continue;
            }
            
            if (count < perPage) {
                Map<String, Object> dataInfo = new HashMap<>();
                dataInfo.put("address", data.getAddress().toString());
                dataInfo.put("type", data.getDataType().getName());
                dataInfo.put("length", data.getLength());
                Object value = data.getValue();
                if (value != null) {
                    dataInfo.put("value", value.toString());
                }
                dataInfo.put("label", data.getLabel());
                dataList.add(dataInfo);
                count++;
            }
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("data", dataList);
        result.put("total", total);
        result.put("page", page);
        result.put("per_page", perPage);
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/data");
        links.put("program", "/program");
        links.put("datatypes", "/datatypes");
        addLinks(response, links);
        
        addPaginationLinks(response, "/data", page, perPage, total);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleGetDataAt(HttpExchange exchange, String addrStr) throws Exception {
        String requestId = getRequestId(exchange);
        Address addr = parseAddressString(addrStr);
        Data data = program.getListing().getDataAt(addr);
        
        if (data == null) {
            sendError(exchange, 404, "No data at address " + addrStr);
            return;
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("address", data.getAddress().toString());
        result.put("type", data.getDataType().getName());
        result.put("length", data.getLength());
        result.put("label", data.getLabel());
        result.put("comment", program.getListing().getComment(CodeUnit.EOL_COMMENT, data.getAddress()));
        
        Object value = data.getValue();
        if (value != null) {
            result.put("value", value.toString());
        }
        
        // Get representation
        result.put("representation", data.getDefaultValueRepresentation());
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/data/" + addrStr);
        links.put("allData", "/data");
        links.put("references", "/data/" + addrStr + "/references");
        links.put("program", "/program");
        addLinks(response, links);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleDataReferences(HttpExchange exchange, String addrStr) throws Exception {
        String requestId = getRequestId(exchange);
        Address addr = parseAddressString(addrStr);
            Data data = program.getListing().getDataAt(addr);
            
            if (data == null) {
                sendError(exchange, 404, "No data at address " + addrStr);
            return;
        }
        
        // Get references TO this data
        ReferenceIterator refsToIter = program.getReferenceManager().getReferencesTo(addr);
        List<Map<String, Object>> toRefs = new ArrayList<>();
        while (refsToIter.hasNext()) {
            Reference ref = refsToIter.next();
            Map<String, Object> refData = new HashMap<>();
            refData.put("from", ref.getFromAddress().toString());
            refData.put("type", ref.getReferenceType().getName());
            toRefs.add(refData);
        }
        
        // Get references FROM this data
        Reference[] refsFrom = program.getReferenceManager().getReferencesFrom(addr);
        List<Map<String, Object>> fromRefs = new ArrayList<>();
        for (Reference ref : refsFrom) {
            Map<String, Object> refData = new HashMap<>();
            refData.put("to", ref.getToAddress().toString());
            refData.put("type", ref.getReferenceType().getName());
            fromRefs.add(refData);
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("address", addrStr);
        result.put("references_to", toRefs);
        result.put("references_from", fromRefs);
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/data/" + addrStr + "/references");
        links.put("data", "/data/" + addrStr);
        links.put("allData", "/data");
        links.put("xrefs", "/xrefs/" + addrStr);
        links.put("program", "/program");
        addLinks(response, links);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    private void registerDataTypeEndpoints() {
        server.createContext("/datatypes", exchange -> {
            String path = exchange.getRequestURI().getPath();
            String query = exchange.getRequestURI().getQuery();
            
            if (path.equals("/datatypes") || path.equals("/datatypes/")) {
                handleListDataTypes(exchange, query);
            } else if (path.equals("/datatypes/structs")) {
                handleListStructs(exchange);
            } else if (path.equals("/datatypes/enums")) {
                handleListEnums(exchange);
            } else if (path.equals("/datatypes/categories")) {
                handleListCategories(exchange);
            } else {
                sendError(exchange, 404, "Endpoint not found");
            }
        });
    }
    
    private void handleListDataTypes(HttpExchange exchange, String query) throws IOException {
        String requestId = getRequestId(exchange);
        DataTypeManager dtm = program.getDataTypeManager();
        List<Map<String, Object>> dataTypes = new ArrayList<>();
        
        Iterator<DataType> iter = dtm.getAllDataTypes();
        int count = 0;
        int maxResults = 100; // Limit results
        
        while (iter.hasNext() && count < maxResults) {
            DataType dt = iter.next();
            Map<String, Object> dtData = new HashMap<>();
            dtData.put("name", dt.getName());
            dtData.put("path", dt.getPathName());
            dtData.put("length", dt.getLength());
            dtData.put("description", dt.getDescription());
            dataTypes.add(dtData);
            count++;
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("datatypes", dataTypes);
        result.put("count", dataTypes.size());
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/datatypes");
        links.put("structs", "/datatypes/structs");
        links.put("enums", "/datatypes/enums");
        links.put("categories", "/datatypes/categories");
        links.put("program", "/program");
        addLinks(response, links);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleListStructs(HttpExchange exchange) throws IOException {
        String requestId = getRequestId(exchange);
        DataTypeManager dtm = program.getDataTypeManager();
        List<Map<String, Object>> structs = new ArrayList<>();
        
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt instanceof Structure) {
                Structure struct = (Structure) dt;
                Map<String, Object> structData = new HashMap<>();
                structData.put("name", struct.getName());
                structData.put("path", struct.getPathName());
                structData.put("length", struct.getLength());
                structData.put("numComponents", struct.getNumComponents());
                structs.add(structData);
            }
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("structs", structs);
        result.put("count", structs.size());
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/datatypes/structs");
        links.put("allDataTypes", "/datatypes");
        links.put("enums", "/datatypes/enums");
        links.put("program", "/program");
        addLinks(response, links);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleListEnums(HttpExchange exchange) throws IOException {
        String requestId = getRequestId(exchange);
        DataTypeManager dtm = program.getDataTypeManager();
        List<Map<String, Object>> enums = new ArrayList<>();
        
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt instanceof ghidra.program.model.data.Enum) {
                ghidra.program.model.data.Enum enumDt = (ghidra.program.model.data.Enum) dt;
                Map<String, Object> enumData = new HashMap<>();
                enumData.put("name", enumDt.getName());
                enumData.put("path", enumDt.getPathName());
                enumData.put("count", enumDt.getCount());
                enums.add(enumData);
            }
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("enums", enums);
        result.put("count", enums.size());
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/datatypes/enums");
        links.put("allDataTypes", "/datatypes");
        links.put("structs", "/datatypes/structs");
        links.put("program", "/program");
        addLinks(response, links);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleListCategories(HttpExchange exchange) throws IOException {
        String requestId = getRequestId(exchange);
        DataTypeManager dtm = program.getDataTypeManager();
        List<Map<String, Object>> categories = new ArrayList<>();
        
        Category root = dtm.getRootCategory();
        addCategoryRecursive(root, categories);
        
        Map<String, Object> result = new HashMap<>();
        result.put("categories", categories);
        result.put("count", categories.size());
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/datatypes/categories");
        links.put("allDataTypes", "/datatypes");
        links.put("program", "/program");
        addLinks(response, links);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    private void addCategoryRecursive(Category category, List<Map<String, Object>> categories) {
        Map<String, Object> catData = new HashMap<>();
        catData.put("name", category.getName());
        catData.put("path", category.getCategoryPathName());
        categories.add(catData);
        
        for (Category subCat : category.getCategories()) {
            addCategoryRecursive(subCat, categories);
        }
    }
    
    private void registerEquateEndpoints() {
        server.createContext("/equates", exchange -> {
            String query = exchange.getRequestURI().getQuery();
            handleListEquates(exchange, query);
        });
    }
    
    private void handleListEquates(HttpExchange exchange, String query) throws IOException {
        String requestId = getRequestId(exchange);
        EquateTable equateTable = program.getEquateTable();
        List<Map<String, Object>> equates = new ArrayList<>();
        
        Iterator<Equate> iter = equateTable.getEquates();
        while (iter.hasNext()) {
            Equate equate = iter.next();
            Map<String, Object> eqData = new HashMap<>();
            eqData.put("name", equate.getName());
            eqData.put("value", equate.getValue());
            eqData.put("referenceCount", equate.getReferenceCount());
            equates.add(eqData);
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("equates", equates);
        result.put("count", equates.size());
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/equates");
        links.put("program", "/program");
        addLinks(response, links);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    private void registerNamespaceEndpoints() {
        server.createContext("/namespaces", exchange -> {
            handleListNamespaces(exchange);
        });
    }
    
    private void handleListNamespaces(HttpExchange exchange) throws IOException {
        String requestId = getRequestId(exchange);
        SymbolTable symbolTable = program.getSymbolTable();
        List<Map<String, Object>> namespaces = new ArrayList<>();
        
        // Get all namespaces by iterating through all symbols
        SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
        Set<Long> seenNamespaces = new HashSet<>();
        
        while (allSymbols.hasNext()) {
            Symbol symbol = allSymbols.next();
            Namespace ns = symbol.getParentNamespace();
            
            if (ns != null && !ns.isGlobal() && !seenNamespaces.contains(ns.getID())) {
                seenNamespaces.add(ns.getID());
                
                Map<String, Object> nsData = new HashMap<>();
                nsData.put("name", ns.getName());
                nsData.put("id", ns.getID());
                
                Namespace parent = ns.getParentNamespace();
                if (parent != null && !parent.isGlobal()) {
                    nsData.put("parent", parent.getName());
                }
                
                // Count symbols in this namespace
                int symbolCount = 0;
                SymbolIterator symIter = symbolTable.getSymbols(ns);
                while (symIter.hasNext()) {
                    symIter.next();
                    symbolCount++;
                }
                nsData.put("symbolCount", symbolCount);
                
                namespaces.add(nsData);
            }
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("namespaces", namespaces);
        result.put("count", namespaces.size());
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/namespaces");
        links.put("symbols", "/symbols");
        links.put("program", "/program");
        addLinks(response, links);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    private void registerProgramEndpoints() {
        server.createContext("/program", exchange -> {
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();
            
            if (path.equals("/program") || path.equals("/program/")) {
                if ("GET".equals(method)) {
                    handleProgramInfo(exchange);
                } else if ("PATCH".equals(method)) {
                    handlePatchProgram(exchange);
                } else {
                    sendError(exchange, 405, "Method not allowed", "METHOD_NOT_ALLOWED");
                }
            } else if (path.equals("/program/imports")) {
                handleProgramImports(exchange);
            } else if (path.equals("/program/exports")) {
                handleProgramExports(exchange);
            } else if (path.equals("/program/entrypoints")) {
                handleProgramEntryPoints(exchange);
            } else if (path.equals("/program/base-address")) {
                handleProgramBaseAddress(exchange);
            } else {
                sendError(exchange, 404, "Endpoint not found");
            }
        });
        
        // Also register /programs/* for compatibility
        server.createContext("/programs", exchange -> {
            String path = exchange.getRequestURI().getPath();
            if (path.startsWith("/programs/current/memory/blocks")) {
                handleListSections(exchange);
            } else {
                sendError(exchange, 404, "Unknown programs endpoint");
            }
        });
    }
    
    private void handleProgramInfo(HttpExchange exchange) throws IOException {
        String requestId = getRequestId(exchange);
        Map<String, Object> result = new HashMap<>();
        result.put("name", program.getName());
        result.put("path", program.getExecutablePath());
        
        // Multiple field names for compatibility
        String imageBaseStr = program.getImageBase().toString();
        result.put("imageBase", imageBaseStr);
        result.put("image_base", imageBaseStr);  // Alternative name
        
        result.put("minAddress", program.getMinAddress().toString());
        result.put("maxAddress", program.getMaxAddress().toString());
        
        String languageStr = program.getLanguageID().getIdAsString();
        result.put("language", languageStr);
        result.put("languageId", languageStr);  // Alternative name
        
        String compilerStr = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
        result.put("compiler", compilerStr);
        result.put("compilerSpecId", compilerStr);  // Alternative name
        
        result.put("creationDate", program.getCreationDate().toString());
        result.put("programId", program.getName());  // Additional field
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/program");
        links.put("imports", "/program/imports");
        links.put("exports", "/program/exports");
        links.put("entrypoints", "/program/entrypoints");
        links.put("baseAddress", "/program/base-address");
        links.put("functions", "/functions");
        links.put("memory", "/memory");
        addLinks(response, links);
        
        sendJsonResponse(exchange, response, 200);
    }

    private void handlePatchProgram(HttpExchange exchange) throws Exception {
        String requestId = getRequestId(exchange);
        Program currentProgram = getCurrentProgram();
        if (currentProgram == null) {
            sendError(exchange, 404, "No program is currently open", "NO_PROGRAM_OPEN");
            return;
        }

        // Parse request body
        JsonObject body;
        try {
            body = parseRequestJson(exchange);
        } catch (IllegalArgumentException e) {
            sendError(exchange, 400, "Invalid JSON body", "INVALID_JSON");
            return;
        }

        String newImageBase = getOptionalString(body, "imageBase");
        if (newImageBase == null) {
            newImageBase = getOptionalString(body, "image_base");
        }

        if (newImageBase == null || newImageBase.isEmpty()) {
            sendError(exchange, 400, "No changes specified. Supported fields: imageBase", "NO_CHANGES");
            return;
        }

        // Parse the new image base address
        Address newBase;
        try {
            newBase = currentProgram.getAddressFactory().getAddress(newImageBase);
            if (newBase == null) {
                sendError(exchange, 400, "Invalid address format: " + newImageBase, "INVALID_ADDRESS");
                return;
            }
        } catch (Exception e) {
            sendError(exchange, 400, "Invalid address format: " + newImageBase + " - " + e.getMessage(), "INVALID_ADDRESS");
            return;
        }

        // Set the new image base within a transaction
        final Address finalNewBase = newBase;
        int txId = currentProgram.startTransaction("Set Image Base");
        try {
            currentProgram.setImageBase(finalNewBase, true);
            currentProgram.endTransaction(txId, true);
        } catch (Exception e) {
            currentProgram.endTransaction(txId, false);
            println("Failed to set image base: " + e.getMessage());
            sendError(exchange, 500, "Failed to set image base: " + e.getMessage(), "SET_IMAGE_BASE_FAILED");
            return;
        }

        // Return updated program info
        Map<String, Object> result = new HashMap<>();
        result.put("name", currentProgram.getName());
        result.put("path", currentProgram.getExecutablePath());
        
        String imageBaseStr = currentProgram.getImageBase().toString();
        result.put("imageBase", imageBaseStr);
        result.put("image_base", imageBaseStr);
        
        result.put("minAddress", currentProgram.getMinAddress().toString());
        result.put("maxAddress", currentProgram.getMaxAddress().toString());
        
        String languageStr = currentProgram.getLanguageID().getIdAsString();
        result.put("language", languageStr);
        result.put("languageId", languageStr);
        
        String compilerStr = currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString();
        result.put("compiler", compilerStr);
        result.put("compilerSpecId", compilerStr);
        
        result.put("creationDate", currentProgram.getCreationDate().toString());
        result.put("programId", currentProgram.getName());

        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/program");
        links.put("imports", "/program/imports");
        links.put("exports", "/program/exports");
        links.put("entrypoints", "/program/entrypoints");
        links.put("baseAddress", "/program/base-address");
        links.put("functions", "/functions");
        links.put("memory", "/memory");
        addLinks(response, links);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleProgramBaseAddress(HttpExchange exchange) throws IOException {
        String requestId = getRequestId(exchange);
        Map<String, Object> result = new HashMap<>();
        
        long baseAddr = program.getImageBase().getOffset();
        result.put("base_address", program.getImageBase().toString());
        result.put("base_address_hex", String.format("0x%X", baseAddr));
        result.put("base_address_dec", baseAddr);
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/program/base-address");
        links.put("program", "/program");
        addLinks(response, links);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleProgramImports(HttpExchange exchange) throws IOException {
        String requestId = getRequestId(exchange);
        ExternalManager extMgr = program.getExternalManager();
        List<Map<String, Object>> imports = new ArrayList<>();
        
        String[] extNames = extMgr.getExternalLibraryNames();
        for (String libName : extNames) {
            ExternalLocationIterator iter = extMgr.getExternalLocations(libName);
            while (iter.hasNext()) {
                ExternalLocation loc = iter.next();
                Map<String, Object> impData = new HashMap<>();
                impData.put("library", libName);
                impData.put("name", loc.getLabel());
                impData.put("address", loc.getAddress().toString());
                impData.put("originalName", loc.getOriginalImportedName());
                imports.add(impData);
            }
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("imports", imports);
        result.put("count", imports.size());
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/program/imports");
        links.put("program", "/program");
        links.put("symbolImports", "/symbols/imports");
        addLinks(response, links);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleProgramExports(HttpExchange exchange) throws IOException {
        String requestId = getRequestId(exchange);
        SymbolTable symTable = program.getSymbolTable();
        List<Map<String, Object>> exports = new ArrayList<>();
        
        SymbolIterator iter = symTable.getExternalSymbols();
        while (iter.hasNext()) {
            Symbol sym = iter.next();
            if (sym.isExternalEntryPoint()) {
                Map<String, Object> expData = new HashMap<>();
                expData.put("name", sym.getName());
                expData.put("address", sym.getAddress().toString());
                exports.add(expData);
            }
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("exports", exports);
        result.put("count", exports.size());
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/program/exports");
        links.put("program", "/program");
        links.put("symbolExports", "/symbols/exports");
        addLinks(response, links);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleProgramEntryPoints(HttpExchange exchange) throws IOException {
        String requestId = getRequestId(exchange);
        SymbolTable symTable = program.getSymbolTable();
        AddressIterator iter = symTable.getExternalEntryPointIterator();
        
        List<Map<String, Object>> entryPoints = new ArrayList<>();
        while (iter.hasNext()) {
            Address addr = iter.next();
            Map<String, Object> epData = new HashMap<>();
            epData.put("address", addr.toString());
            
            Symbol[] symbols = symTable.getSymbols(addr);
            if (symbols.length > 0) {
                epData.put("name", symbols[0].getName());
            }
            
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func != null) {
                epData.put("function", func.getName());
            }
            
            entryPoints.add(epData);
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("entryPoints", entryPoints);
        result.put("count", entryPoints.size());
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/program/entrypoints");
        links.put("program", "/program");
        links.put("functions", "/functions");
        addLinks(response, links);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    // ==================== SECTIONS ENDPOINTS (CRITICAL for network_config_discover) ====================
    private void registerSectionEndpoints() {
        server.createContext("/sections", exchange -> {
            safeHandle(exchange, ex -> {
                String method = ex.getRequestMethod();
                String path = ex.getRequestURI().getPath();
                String query = ex.getRequestURI().getQuery();
                
                if (!method.equals("GET")) {
                    sendError(ex, 405, "Method not allowed");
                    return;
                }
                
                // Parse path: /sections or /sections/by-name/{name}/read
                String[] segments = path.split("/");
                
                if (segments.length == 2 || (segments.length == 3 && segments[2].isEmpty())) {
                    // /sections - list all sections
                    handleListSections(ex);
                } else if (segments.length >= 5 && segments[2].equals("by-name") && segments[4].equals("read")) {
                    // /sections/by-name/{name}/read
                    String sectionName = segments[3];
                    handleReadSectionByName(ex, sectionName, query);
                } else {
                    sendError(ex, 404, "Unknown sections endpoint");
                }
            });
        });
    }
    
    private void handleListSections(HttpExchange exchange) throws IOException {
        String requestId = getRequestId(exchange);
        Memory memory = program.getMemory();
        List<Map<String, Object>> sections = new ArrayList<>();
        
        for (MemoryBlock block : memory.getBlocks()) {
            Map<String, Object> sectionData = new HashMap<>();
            sectionData.put("name", block.getName());
            sectionData.put("start", block.getStart().toString());
            sectionData.put("end", block.getEnd().toString());
            sectionData.put("size", block.getSize());
            
            // Build permissions string (rwx- format for consistency with /memory/blocks)
            StringBuilder perms = new StringBuilder();
            perms.append(block.isRead() ? "r" : "-");
            perms.append(block.isWrite() ? "w" : "-");
            perms.append(block.isExecute() ? "x" : "-");
            perms.append(block.isVolatile() ? "v" : "-");
            String permString = perms.toString();
            
            sectionData.put("permissions", permString);
            sectionData.put("flags", permString); // Alias for compatibility
            
            // Add explicit boolean flags for easier parsing
            sectionData.put("read", block.isRead());
            sectionData.put("write", block.isWrite());
            sectionData.put("execute", block.isExecute());
            sectionData.put("executable", block.isExecute()); // Additional alias
            
            sectionData.put("type", block.getType().toString());
            sectionData.put("initialized", block.isInitialized());
            sectionData.put("isInitialized", block.isInitialized()); // Match /memory/blocks
            sectionData.put("isLoaded", block.isLoaded());
            sectionData.put("isMapped", block.isMapped());
            sections.add(sectionData);
        }
        
        Map<String, Object> response = buildHateoasResponse(true, sections, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/sections");
        links.put("memory", "/memory");
        links.put("segments", "/segments");
        links.put("program", "/program");
        addLinks(response, links);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleReadSectionByName(HttpExchange exchange, String sectionName, String query) throws Exception {
        String requestId = getRequestId(exchange);
        Map<String, String> params = parseQuery(query);
        String format = params.getOrDefault("format", "hex");
        
        Memory memory = program.getMemory();
        MemoryBlock block = memory.getBlock(sectionName);
        
        if (block == null) {
            sendError(exchange, 404, "Section not found: " + sectionName);
            return;
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("name", sectionName);
        result.put("start", block.getStart().toString());
        result.put("end", block.getEnd().toString());
        result.put("size", block.getSize());
        
        // Read the section data with safety limit
        long size = block.getSize();
        boolean truncated = false;
        if (size > 10 * 1024 * 1024) { // Limit to 10MB
            size = 10 * 1024 * 1024;
            truncated = true;
        }
        
        byte[] bytes = new byte[(int)size];
        memory.getBytes(block.getStart(), bytes);
        
        if ("base64".equalsIgnoreCase(format)) {
            result.put("data", Base64.getEncoder().encodeToString(bytes));
            result.put("format", "base64");
        } else {
            // Default to hex
            StringBuilder hex = new StringBuilder();
            for (byte b : bytes) {
                hex.append(String.format("%02x", b));
            }
            result.put("data", hex.toString());
            result.put("format", "hex");
        }
        
        if (truncated) {
            result.put("truncated", true);
            result.put("truncated_at", size);
        }
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/sections/" + sectionName);
        links.put("allSections", "/sections");
        links.put("memory", "/memory");
        addLinks(response, links);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    private void registerSegmentEndpoints() {
        server.createContext("/segments", exchange -> {
            safeHandle(exchange, ex -> {
                String method = ex.getRequestMethod();
                String path = ex.getRequestURI().getPath();
                String query = ex.getRequestURI().getQuery();
                
                if (!method.equals("GET")) {
                    sendError(ex, 405, "Method not allowed");
                    return;
                }
                
                // Parse path: /segments or /segments/by-name/{name}/read
                String[] segments = path.split("/");
                
                if (segments.length == 2 || (segments.length == 3 && segments[2].isEmpty())) {
                    // /segments - list all segments
                    handleListSegments(ex);
                } else if (segments.length >= 5 && segments[2].equals("by-name") && segments[4].equals("read")) {
                    // /segments/by-name/{name}/read - read segment data by name
                    String segmentName = segments[3];
                    handleReadSegmentByName(ex, segmentName, query);
                } else {
                    sendError(ex, 404, "Unknown segments endpoint");
                }
            });
        });
    }
    
    private void handleListSegments(HttpExchange exchange) throws IOException {
        String requestId = getRequestId(exchange);
        Memory memory = program.getMemory();
        List<Map<String, Object>> segments = new ArrayList<>();
        
        for (MemoryBlock block : memory.getBlocks()) {
            Map<String, Object> segData = new HashMap<>();
            segData.put("name", block.getName());
            segData.put("start", block.getStart().toString());
            segData.put("end", block.getEnd().toString());
            segData.put("size", block.getSize());
            segData.put("read", block.isRead());
            segData.put("write", block.isWrite());
            segData.put("execute", block.isExecute());
            segData.put("initialized", block.isInitialized());
            segData.put("type", block.getType().toString());
            segments.add(segData);
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("segments", segments);
        result.put("count", segments.size());
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/segments");
        links.put("sections", "/sections");
        links.put("memory", "/memory");
        links.put("program", "/program");
        addLinks(response, links);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleReadSegmentByName(HttpExchange exchange, String segmentName, String query) throws IOException {
        String requestId = getRequestId(exchange);
        String format = "base64"; // default format
        
        // Parse query parameters for format
        if (query != null) {
            String[] params = query.split("&");
            for (String param : params) {
                String[] kv = param.split("=");
                if (kv.length == 2 && kv[0].equals("format")) {
                    format = kv[1];
                }
            }
        }
        
        Memory memory = program.getMemory();
        MemoryBlock targetBlock = null;
        
        // Find the segment by name (case-insensitive)
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.getName().equalsIgnoreCase(segmentName)) {
                targetBlock = block;
                break;
            }
        }
        
        if (targetBlock == null) {
            sendError(exchange, 404, "Segment not found: " + segmentName);
            return;
        }
        
        long size = targetBlock.getSize();
        if (size > 10 * 1024 * 1024) { // 10MB limit
            sendError(exchange, 413, "Segment too large (max 10MB)");
            return;
        }
        
        byte[] data = new byte[(int) size];
        try {
            targetBlock.getBytes(targetBlock.getStart(), data);
        } catch (Exception e) {
            sendError(exchange, 500, "Failed to read segment data: " + e.getMessage());
            return;
        }
        
        Map<String, Object> segmentInfo = new HashMap<>();
        segmentInfo.put("name", targetBlock.getName());
        segmentInfo.put("start", targetBlock.getStart().toString());
        segmentInfo.put("end", targetBlock.getEnd().toString());
        segmentInfo.put("size", size);
        segmentInfo.put("read", targetBlock.isRead());
        segmentInfo.put("write", targetBlock.isWrite());
        segmentInfo.put("execute", targetBlock.isExecute());
        segmentInfo.put("initialized", targetBlock.isInitialized());
        
        Map<String, Object> result = new HashMap<>();
        result.put("segment_info", segmentInfo);
        
        // Add data in requested format
        if (format.equals("hex")) {
            StringBuilder hex = new StringBuilder();
            for (byte b : data) {
                hex.append(String.format("%02X ", b & 0xFF));
            }
            result.put("data", hex.toString().trim());
        } else if (format.equals("base64")) {
            result.put("data", java.util.Base64.getEncoder().encodeToString(data));
        } else if (format.equals("string")) {
            result.put("data", new String(data, java.nio.charset.StandardCharsets.ISO_8859_1));
        } else {
            result.put("data", java.util.Base64.getEncoder().encodeToString(data));
        }
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/segments/by-name/" + segmentName + "/read");
        links.put("segment_list", "/segments");
        links.put("section_list", "/sections");
        links.put("memory", "/memory");
        addLinks(response, links);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    private void registerVariableEndpoints() {
        server.createContext("/variables", exchange -> {
            String path = exchange.getRequestURI().getPath();
            
            if (path.equals("/variables/global")) {
                handleGlobalVariables(exchange);
            } else {
                sendError(exchange, 404, "Endpoint not found");
            }
        });
    }
    
    private void handleGlobalVariables(HttpExchange exchange) throws IOException {
        String requestId = getRequestId(exchange);
        SymbolTable symTable = program.getSymbolTable();
        List<Map<String, Object>> globals = new ArrayList<>();
        
        SymbolIterator iter = symTable.getAllSymbols(true);
        while (iter.hasNext()) {
            Symbol sym = iter.next();
            if (sym.getSymbolType() == SymbolType.LABEL) {
                Data data = program.getListing().getDataAt(sym.getAddress());
                if (data != null) {
                    Map<String, Object> varData = new HashMap<>();
                    varData.put("name", sym.getName());
                    varData.put("address", sym.getAddress().toString());
                    varData.put("type", data.getDataType().getName());
                    varData.put("length", data.getLength());
                    globals.add(varData);
                }
            }
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("variables", globals);
        result.put("count", globals.size());
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/variables/global");
        links.put("symbols", "/symbols");
        links.put("program", "/program");
        addLinks(response, links);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    // ==================== COMMENTS ENDPOINTS ====================
    private void registerCommentsEndpoints() {
        server.createContext("/comments", exchange -> {
            safeHandle(exchange, ex -> {
                String query = ex.getRequestURI().getQuery();
                Map<String, String> params = parseQuery(query);
                String addr = params.get("address");
                
                if (addr != null) {
                    handleGetComments(ex, addr);
                } else {
                    sendError(ex, 400, "Missing address parameter");
                }
            });
        });
    }
    
    private void handleGetComments(HttpExchange exchange, String addrStr) throws Exception {
        String requestId = getRequestId(exchange);
        Address addr = parseAddressString(addrStr);
        Listing listing = program.getListing();
        
        Map<String, Object> comments = new HashMap<>();
        comments.put("address", addrStr);
        comments.put("plate", listing.getComment(CodeUnit.PLATE_COMMENT, addr));
        comments.put("pre", listing.getComment(CodeUnit.PRE_COMMENT, addr));
        comments.put("post", listing.getComment(CodeUnit.POST_COMMENT, addr));
        comments.put("eol", listing.getComment(CodeUnit.EOL_COMMENT, addr));
        comments.put("repeatable", listing.getComment(CodeUnit.REPEATABLE_COMMENT, addr));
        
        Map<String, Object> response = buildHateoasResponse(true, comments, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/comments?address=" + addrStr);
        links.put("program", "/program");
        addLinks(response, links);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    // ==================== ANALYSIS ENDPOINTS ====================
    // ==================== ANALYSIS ENDPOINTS ====================
    private void registerAnalysisEndpoints() {
        server.createContext("/analysis", exchange -> {
            safeHandle(exchange, ex -> {
                String method = ex.getRequestMethod();
                String path = ex.getRequestURI().getPath();
                
                if (!method.equals("GET")) {
                    sendError(ex, 405, "Method not allowed");
                    return;
                }
                
                String[] segments = path.split("/");
                
                if (segments.length == 2 || (segments.length == 3 && segments[2].isEmpty())) {
                    // /analysis or /analysis/
                    handleAnalysisStatus(ex);
                } else if (segments.length == 3 && segments[2].equals("status")) {
                    // /analysis/status
                    handleAnalysisStatus(ex);
                } else {
                    sendError(ex, 404, "Invalid analysis endpoint path");
                }
            });
        });
    }
    
    private void handleAnalysisStatus(HttpExchange exchange) throws Exception {
        String requestId = getRequestId(exchange);
        Map<String, Object> result = new HashMap<>();
        
        // Get analysis status
        boolean analyzed = program.getOptions(Program.PROGRAM_INFO).getBoolean("Analyzed", false);
        result.put("analyzed", analyzed);
        result.put("programName", program.getName());
        result.put("language", program.getLanguage().getLanguageID().getIdAsString());
        result.put("compiler", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
        
        // Get function count
        result.put("functionCount", program.getFunctionManager().getFunctionCount());
        
        // Get symbol count
        result.put("symbolCount", program.getSymbolTable().getNumSymbols());
        
        // Get memory info
        Memory memory = program.getMemory();
        result.put("memorySize", memory.getSize());
        result.put("memoryBlocks", memory.getBlocks().length);
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/analysis");
        links.put("program", "/program");
        links.put("functions", "/functions");
        links.put("symbols", "/symbols");
        addLinks(response, links);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    // ==================== CLASS ENDPOINTS ====================
    // ==================== CLASS ENDPOINTS ====================
    private void registerClassEndpoints() {
        server.createContext("/classes", exchange -> {
            safeHandle(exchange, ex -> {
                String method = ex.getRequestMethod();
                String path = ex.getRequestURI().getPath();
                String query = ex.getRequestURI().getQuery();
                
                if (!method.equals("GET")) {
                    sendError(ex, 405, "Method not allowed");
                    return;
                }
                
                // Parse path segments: /classes/[className]/[action]
                String[] segments = path.split("/");
                
                if (segments.length == 2 || (segments.length == 3 && segments[2].isEmpty())) {
                    // /classes or /classes/
                    handleListClasses(ex, query);
                } else if (segments.length == 3) {
                    // /classes/{className}
                    handleGetClass(ex, segments[2]);
                } else if (segments.length == 4) {
                    // /classes/{className}/{action}
                    String className = segments[2];
                    String action = segments[3];
                    
                    switch (action) {
                        case "methods":
                            handleClassMethods(ex, className);
                            break;
                        case "fields":
                            handleClassFields(ex, className);
                            break;
                        default:
                            sendError(ex, 404, "Unknown class action: " + action);
                    }
                } else {
                    sendError(ex, 404, "Invalid class endpoint path");
                }
            });
        });
    }
    
    private void handleListClasses(HttpExchange exchange, String query) throws Exception {
        String requestId = getRequestId(exchange);
        SymbolTable symbolTable = program.getSymbolTable();
        List<Map<String, Object>> classes = new ArrayList<>();
        
        // Find all class namespaces
        SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
        Set<String> seenClasses = new HashSet<>();
        
        while (allSymbols.hasNext()) {
            Symbol symbol = allSymbols.next();
            Namespace ns = symbol.getParentNamespace();
            
            if (ns != null && ns instanceof GhidraClass && !seenClasses.contains(ns.getName())) {
                seenClasses.add(ns.getName());
                
                Map<String, Object> classData = new HashMap<>();
                classData.put("name", ns.getName());
                classData.put("namespace", ns.getParentNamespace().getName());
                classes.add(classData);
            }
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("classes", classes);
        result.put("count", classes.size());
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/classes");
        links.put("program", "/program");
        addLinks(response, links);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleGetClass(HttpExchange exchange, String className) throws Exception {
        String requestId = getRequestId(exchange);
        SymbolTable symbolTable = program.getSymbolTable();
        
        // Find the class namespace
        List<Symbol> symbols = symbolTable.getGlobalSymbols(className);
        Namespace classNamespace = null;
        
        for (Symbol sym : symbols) {
            if (sym.getObject() instanceof Namespace) {
                Namespace ns = (Namespace) sym.getObject();
                if (ns instanceof GhidraClass) {
                    classNamespace = ns;
                    break;
                }
            }
        }
        
        if (classNamespace == null) {
            sendError(exchange, 404, "Class not found: " + className);
            return;
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("name", classNamespace.getName());
        result.put("namespace", classNamespace.getParentNamespace().getName());
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/classes/" + className);
        links.put("allClasses", "/classes");
        links.put("methods", "/classes/" + className + "/methods");
        links.put("fields", "/classes/" + className + "/fields");
        addLinks(response, links);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleClassMethods(HttpExchange exchange, String className) throws Exception {
        String requestId = getRequestId(exchange);
        SymbolTable symbolTable = program.getSymbolTable();
        FunctionManager funcMgr = program.getFunctionManager();
        List<Map<String, Object>> methods = new ArrayList<>();
        
        // Find all functions in the class namespace
        SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
        
        while (allSymbols.hasNext()) {
            Symbol symbol = allSymbols.next();
            
            if (symbol.getSymbolType() == SymbolType.FUNCTION) {
                Namespace parent = symbol.getParentNamespace();
                if (parent != null && parent.getName().equals(className)) {
                    Function func = funcMgr.getFunctionAt(symbol.getAddress());
                    if (func != null) {
                        Map<String, Object> methodData = new HashMap<>();
                        methodData.put("name", func.getName());
                        methodData.put("address", func.getEntryPoint().toString());
                        methodData.put("signature", func.getPrototypeString(true, false));
                        methods.add(methodData);
                    }
                }
            }
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("className", className);
        result.put("methods", methods);
        result.put("count", methods.size());
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/classes/" + className + "/methods");
        links.put("class", "/classes/" + className);
        links.put("allClasses", "/classes");
        addLinks(response, links);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    private void handleClassFields(HttpExchange exchange, String className) throws Exception {
        String requestId = getRequestId(exchange);
        // For now, return empty fields (would need more complex logic to detect fields)
        Map<String, Object> result = new HashMap<>();
        result.put("className", className);
        result.put("fields", new ArrayList<>());
        result.put("count", 0);
        result.put("message", "Field detection not yet implemented in headless mode");
        
        Map<String, Object> response = buildHateoasResponse(true, result, requestId);
        
        Map<String, String> links = new HashMap<>();
        links.put("self", "/classes/" + className + "/fields");
        links.put("class", "/classes/" + className);
        links.put("methods", "/classes/" + className + "/methods");
        addLinks(response, links);
        
        sendJsonResponse(exchange, response, 200);
    }
    
    // ==================== HELPER METHODS ====================
    
    /**
     * Parse address from various formats: 005f1030, 0x005f1030, 0X005F1030
     */
    private Address parseAddressString(String addrStr) throws Exception {
        if (addrStr == null || addrStr.isEmpty()) {
            throw new IllegalArgumentException("Address cannot be null or empty");
        }
        
        // Remove 0x or 0X prefix if present
        String cleanAddr = addrStr;
        if (addrStr.toLowerCase().startsWith("0x")) {
            cleanAddr = addrStr.substring(2);
        }
        
        // Ensure it's valid hex
        if (!cleanAddr.matches("[0-9a-fA-F]+")) {
            throw new IllegalArgumentException("Invalid hex address: " + addrStr);
        }
        
        try {
            return program.getAddressFactory().getAddress(cleanAddr);
        } catch (Exception e) {
            throw new IllegalArgumentException("Cannot parse address: " + addrStr + " - " + e.getMessage());
        }
    }
    
    /**
     * Log incoming request for debugging
     */
    private void logRequest(HttpExchange exchange) {
        String method = exchange.getRequestMethod();
        String path = exchange.getRequestURI().getPath();
        String query = exchange.getRequestURI().getQuery();
        String logMsg = String.format("[%s] %s%s", method, path, query != null ? "?" + query : "");
        println(logMsg);
    }
    
    /**
     * Safe handler wrapper that catches exceptions and returns proper errors
     */
    private void safeHandle(HttpExchange exchange, ThrowingConsumer<HttpExchange> handler) {
        try {
            logRequest(exchange);
            handler.accept(exchange);
        } catch (IllegalArgumentException e) {
            try {
                sendError(exchange, 400, e.getMessage());
            } catch (IOException ioe) {
                println("ERROR: Failed to send error response: " + ioe.getMessage());
            }
        } catch (Exception e) {
            try {
                println("ERROR: " + e.getMessage());
                e.printStackTrace();
                sendError(exchange, 500, "Internal server error: " + e.getMessage());
            } catch (IOException ioe) {
                println("ERROR: Failed to send error response: " + ioe.getMessage());
            }
        }
    }
    
    // ==================== PUBLIC ACCESSOR METHODS ====================
    
    /**
     * Get the current program (for instance management)
     */
    public Program getCurrentProgram() {
        return program;
    }
    
    /**
     * Check if this is the base instance
     */
    public boolean isBaseInstance() {
        return true; // In headless mode, each script is its own base
    }
    
    /**
     * Get the port this server is running on
     */
    public int getPort() {
        return port;
    }
    
    /**
     * Get all active instances
     */
    public static Map<Integer, GhidraMCPHeadlessServer> getActiveInstances() {
        return activeInstances;
    }
    
    // ==================== HATEOAS RESPONSE HELPERS ====================
    
    /**
     * Build a HATEOAS-compliant response with id, instance, _links fields
     */
    private Map<String, Object> buildHateoasResponse(boolean success, Object result, String requestId) {
        HeadlessResponseBuilder builder = new HeadlessResponseBuilder(requestId);
        builder.success(success);
        if (result != null) {
            builder.result(result);
        }
        return builder.build();
    }
    
    /**
     * Add HATEOAS links to a response
     */
    private void addLinks(Map<String, Object> response, Map<String, ?> links) {
        if (links == null || links.isEmpty()) {
            return;
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> linksObj = (Map<String, Object>) response.get("_links");
        if (linksObj == null) {
            linksObj = new LinkedHashMap<>();
            response.put("_links", linksObj);
        }

        for (Map.Entry<String, ?> entry : links.entrySet()) {
            String rel = entry.getKey();
            Object value = entry.getValue();
            if (value instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> link = new LinkedHashMap<>((Map<String, Object>) value);
                linksObj.put(rel, link);
            } else if (value instanceof String) {
                Map<String, Object> link = new LinkedHashMap<>();
                link.put("href", value);
                linksObj.put(rel, link);
            }
        }
    }
    
    /**
     * Add pagination links using offset/limit semantics.
     */
    private void addOffsetPaginationLinks(Map<String, Object> response, String basePath, String queryPrefix, int offset, int limit, int total) {
        Map<String, Object> links = new LinkedHashMap<>();
        String prefix = basePath;
        if (queryPrefix != null && !queryPrefix.isEmpty()) {
            if (!queryPrefix.endsWith("&") && !queryPrefix.endsWith("?")) {
                queryPrefix = queryPrefix + "&";
            }
            if (!queryPrefix.startsWith("?")) {
                queryPrefix = "?" + queryPrefix;
            }
            prefix = basePath + queryPrefix;
        } else {
            prefix = basePath + "?";
        }

        links.put("self", Map.of("href", prefix + "offset=" + offset + "&limit=" + limit));

        if (offset > 0) {
            int prevOffset = Math.max(0, offset - limit);
            links.put("prev", Map.of("href", prefix + "offset=" + prevOffset + "&limit=" + limit));
        }

        if (offset + limit < total) {
            int nextOffset = offset + limit;
            links.put("next", Map.of("href", prefix + "offset=" + nextOffset + "&limit=" + limit));
        }

        addLinks(response, links);
    }

    /**
     * Backwards-compatible pagination helper using page/per_page inputs.
     * Converts to offset/limit semantics internally.
     */
    private void addPaginationLinks(Map<String, Object> response, String basePath, int page, int perPage, int total) {
        int safePage = Math.max(page, 1);
        int safePerPage = Math.max(perPage, 1);
        int offset = (safePage - 1) * safePerPage;
        addOffsetPaginationLinks(response, basePath, "", offset, safePerPage, total);
    }
    
    /**
     * Add standard resource links (self, program)
     */
    private void addResourceLinks(Map<String, Object> response, String selfHref) {
        Map<String, String> links = new HashMap<>();
        links.put("self", selfHref);
        links.put("program", "/program");
        addLinks(response, links);
    }
    
    /**
     * Get request ID from headers or generate new one
     */
    private String getRequestId(HttpExchange exchange) {
        String requestId = exchange.getRequestHeaders().getFirst("X-Request-ID");
        return requestId != null ? requestId : java.util.UUID.randomUUID().toString();
    }
    
    /**
     * Send HATEOAS response
     */
    private void sendHateoasResponse(HttpExchange exchange, boolean success, Object result, Map<String, String> links) throws IOException {
        String requestId = getRequestId(exchange);
        Map<String, Object> response = buildHateoasResponse(success, result, requestId);
        if (links != null) {
            addLinks(response, links);
        }
        sendJsonResponse(exchange, response, 200);
    }
    
    // ==================== UTILITY METHODS ====================

    private class HeadlessResponseBuilder {
        private final Map<String, Object> response = new LinkedHashMap<>();
        private final Map<String, Object> links = new LinkedHashMap<>();

        HeadlessResponseBuilder(String requestId) {
            response.put("id", requestId != null ? requestId : UUID.randomUUID().toString());
            response.put("instance", "http://localhost:" + port);
        }

        HeadlessResponseBuilder success(boolean success) {
            response.put("success", success);
            return this;
        }

        HeadlessResponseBuilder result(Object result) {
            response.put("result", result);
            return this;
        }

        HeadlessResponseBuilder metadata(String key, Object value) {
            if (value != null) {
                response.put(key, value);
            }
            return this;
        }

        HeadlessResponseBuilder metadata(Map<String, Object> metadata) {
            if (metadata != null) {
                for (Map.Entry<String, Object> entry : metadata.entrySet()) {
                    metadata(entry.getKey(), entry.getValue());
                }
            }
            return this;
        }

        HeadlessResponseBuilder error(String message, String code) {
            Map<String, Object> error = new LinkedHashMap<>();
            error.put("message", message);
            if (code != null && !code.isEmpty()) {
                error.put("code", code);
            }
            response.put("error", error);
            response.put("success", false);
            return this;
        }

        HeadlessResponseBuilder addLink(String rel, String href) {
            Map<String, Object> link = new LinkedHashMap<>();
            link.put("href", href);
            links.put(rel, link);
            return this;
        }

        HeadlessResponseBuilder addLink(String rel, String href, String method) {
            Map<String, Object> link = new LinkedHashMap<>();
            link.put("href", href);
            link.put("method", method);
            links.put(rel, link);
            return this;
        }

        Map<String, Object> build() {
            if (!links.isEmpty()) {
                response.put("_links", links);
            }
            return response;
        }
    }
    
    @FunctionalInterface
    interface ThrowingConsumer<T> {
        void accept(T t) throws Exception;
    }
    
    private void sendJsonResponse(HttpExchange exchange, Object data, int statusCode) throws IOException {
        String json = toJson(data);
        byte[] bytes = json.getBytes("UTF-8");
        
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
    
    private void sendError(HttpExchange exchange, int statusCode, String message) throws IOException {
        sendError(exchange, statusCode, message, null);
    }

    private void sendError(HttpExchange exchange, int statusCode, String message, String code) throws IOException {
        String requestId = getRequestId(exchange);
        HeadlessResponseBuilder builder = new HeadlessResponseBuilder(requestId)
            .success(false)
            .error(message, code);
        sendJsonResponse(exchange, builder.build(), statusCode);
    }

    private JsonObject parseRequestJson(HttpExchange exchange) throws IOException {
        try (InputStream is = exchange.getRequestBody()) {
            byte[] data = is.readAllBytes();
            if (data.length == 0) {
                return new JsonObject();
            }

            String body = new String(data, StandardCharsets.UTF_8);
            if (body.trim().isEmpty()) {
                return new JsonObject();
            }

            try {
                JsonObject json = gson.fromJson(body, JsonObject.class);
                return json != null ? json : new JsonObject();
            } catch (JsonSyntaxException e) {
                throw new IllegalArgumentException("Invalid JSON body", e);
            }
        }
    }

    private String getOptionalString(JsonObject json, String member) {
        if (json == null || !json.has(member) || json.get(member).isJsonNull()) {
            return null;
        }
        return json.get(member).getAsString();
    }

    private boolean renameFunction(Function function, String newName) {
        Program funcProgram = function.getProgram();
        int transactionId = funcProgram.startTransaction("Rename Function");
        boolean success = false;
        try {
            function.setName(newName, SourceType.USER_DEFINED);
            success = true;
        } catch (Exception e) {
            println("ERROR: Failed to rename function: " + e.getMessage());
        } finally {
            funcProgram.endTransaction(transactionId, success);
        }
        return success;
    }

    private boolean updateFunctionSignature(Function function, String signature) {
        Program funcProgram = function.getProgram();
        int transactionId = funcProgram.startTransaction("Set Function Signature");
        boolean success = false;
        try {
            success = GhidraUtil.setFunctionSignature(function, signature);
        } catch (Exception e) {
            println("ERROR: Failed to set function signature: " + e.getMessage());
            success = false;
        } finally {
            funcProgram.endTransaction(transactionId, success);
        }
        return success;
    }

    private boolean updateFunctionComment(Function function, String comment) {
        Program funcProgram = function.getProgram();
        int transactionId = funcProgram.startTransaction("Set Function Comment");
        boolean success = false;
        try {
            function.setComment(comment);
            success = true;
        } catch (Exception e) {
            println("ERROR: Failed to set function comment: " + e.getMessage());
        } finally {
            funcProgram.endTransaction(transactionId, success);
        }
        return success;
    }

    private int parseIntOrDefault(String value, int defaultValue) {
        if (value == null || value.isEmpty()) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ex) {
            return defaultValue;
        }
    }
    
    private Map<String, String> parseQuery(String query) {
        Map<String, String> params = new HashMap<>();
        if (query != null && !query.isEmpty()) {
            String[] pairs = query.split("&");
            for (String pair : pairs) {
                String[] kv = pair.split("=", 2);
                if (kv.length == 2) {
                    params.put(kv[0], kv[1]);
                }
            }
        }
        return params;
    }
    
    private String toJson(Object obj) {
        if (obj instanceof Map) {
            return mapToJson((Map<String, Object>) obj);
        } else if (obj instanceof List) {
            return listToJson((List<?>) obj);
        }
        return "{}";
    }
    
    private String mapToJson(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            sb.append("\"").append(escapeJson(entry.getKey())).append("\":");
            
            Object value = entry.getValue();
            if (value == null) {
                sb.append("null");
            } else if (value instanceof String) {
                sb.append("\"").append(escapeJson((String) value)).append("\"");
            } else if (value instanceof Map) {
                sb.append(mapToJson((Map<String, Object>) value));
            } else if (value instanceof List) {
                sb.append(listToJson((List<?>) value));
            } else if (value instanceof Boolean || value instanceof Number) {
                sb.append(value.toString());
            } else {
                sb.append("\"").append(escapeJson(value.toString())).append("\"");
            }
        }
        sb.append("}");
        return sb.toString();
    }
    
    private String listToJson(List<?> list) {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (Object item : list) {
            if (!first) sb.append(",");
            first = false;
            
            if (item instanceof String) {
                sb.append("\"").append(escapeJson((String) item)).append("\"");
            } else if (item instanceof Map) {
                sb.append(mapToJson((Map<String, Object>) item));
            } else if (item instanceof List) {
                sb.append(listToJson((List<?>) item));
            } else {
                sb.append("\"").append(escapeJson(item.toString())).append("\"");
            }
        }
        sb.append("]");
        return sb.toString();
    }
    
    private String escapeJson(String str) {
        if (str == null) return "";
        return str.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }
}
