package au.federation.ghidra;

// Imports for HTTP server and endpoints
import au.federation.ghidra.api.*;
import au.federation.ghidra.endpoints.*;
import au.federation.ghidra.util.*;
import au.federation.ghidra.model.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

// For JSON response handling
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.Headers;

// Ghidra script imports
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;

/**
 * GhidraMCP Headless Script
 * 
 * This script provides the same HTTP API as the GhidraMCP plugin but runs in headless mode.
 * It can be run using Ghidra's analyzeHeadless command:
 * 
 * analyzeHeadless <project_location> <project_name> -import <file> -scriptPath <script_dir> 
 *   -postScript GhidraMCPHeadlessScript.java
 * 
 * Or on an existing project:
 * 
 * analyzeHeadless <project_location> <project_name> -process <file_name> -scriptPath <script_dir>
 *   -postScript GhidraMCPHeadlessScript.java
 * 
 * Environment Variables:
 *   GHIDRAMCP_PORT - Port for HTTP server (default: 8192)
 *   GHIDRAMCP_KEEP_RUNNING - Keep server running after script completes (default: true)
 * 
 * The HTTP API is identical to the plugin version, ensuring ghidra_mcp_server.py works without modification.
 */
public class GhidraMCPHeadlessScript extends GhidraScript {
    
    // Shared instance tracking - using Object to support both plugin and script instances
    public static final Map<Integer, Object> activeInstances = new ConcurrentHashMap<>();
    private static final Object baseInstanceLock = new Object();
    
    private HttpServer server;
    private int port;
    private boolean isBaseInstance = false;
    private HeadlessPluginState pluginState;
    
    /**
     * Check if this is the base instance.
     * @return true if this is the base instance
     */
    public boolean isBaseInstance() {
        return isBaseInstance;
    }
    
    /**
     * Get the port this instance is running on.
     * @return the HTTP server port
     */
    public int getPort() {
        return port;
    }
    
    @Override
    public void run() throws Exception {
        println("===========================================");
        println("GhidraMCP Headless Script Starting");
        println("===========================================");
        
        // Determine port from environment or use default
        String portEnv = System.getenv("GHIDRAMCP_PORT");
        int requestedPort = ApiConstants.DEFAULT_PORT;
        if (portEnv != null) {
            try {
                requestedPort = Integer.parseInt(portEnv);
                println("Using port from GHIDRAMCP_PORT environment: " + requestedPort);
            } catch (NumberFormatException e) {
                printerr("Invalid GHIDRAMCP_PORT value: " + portEnv + ", using default: " + requestedPort);
            }
        }
        
        // Find available port
        this.port = findAvailablePort(requestedPort);
        activeInstances.put(port, this);
        
        // Determine if this is base instance
        synchronized (baseInstanceLock) {
            if (port == ApiConstants.DEFAULT_PORT || activeInstances.get(ApiConstants.DEFAULT_PORT) == null) {
                this.isBaseInstance = true;
                println("Starting as base instance on port " + port);
            }
        }
        
        // Create plugin state wrapper
        this.pluginState = new HeadlessPluginState(this, port);
        
        // Get current program
        Program program = getCurrentProgram();
        if (program == null) {
            printerr("WARNING: No program loaded. Some endpoints may not function.");
            println("Consider running with -import or -process to load a program.");
        } else {
            println("Current program: " + program.getName());
            println("  Architecture: " + program.getLanguage().getLanguageID().getIdAsString());
            println("  Processor: " + program.getLanguage().getProcessor().toString());
        }
        
        // Start HTTP server
        try {
            startServer();
            println("HTTP server started successfully on port " + port);
            println("Access at: http://localhost:" + port + "/");
            
            // Determine if we should keep running
            String keepRunningEnv = System.getenv("GHIDRAMCP_KEEP_RUNNING");
            boolean keepRunning = (keepRunningEnv == null) || Boolean.parseBoolean(keepRunningEnv);
            
            if (keepRunning) {
                println("Server will keep running (GHIDRAMCP_KEEP_RUNNING=true)");
                println("Press Ctrl+C to stop the server");
                
                // Keep the script running
                keepServerRunning();
            } else {
                println("Server will stop when script completes (GHIDRAMCP_KEEP_RUNNING=false)");
            }
            
        } catch (IOException e) {
            printerr("Failed to start HTTP server on port " + port);
            e.printStackTrace();
            throw e;
        }
    }
    
    /**
     * Keep the server running indefinitely.
     * This method blocks until interrupted or the JVM exits.
     */
    private void keepServerRunning() {
        println("===========================================");
        println("GhidraMCP Server Running");
        println("Port: " + port);
        println("Instance: " + (isBaseInstance ? "BASE" : "Secondary"));
        println("===========================================");
        
        // Add shutdown hook to clean up
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            println("Shutdown hook triggered - cleaning up...");
            cleanup();
        }));
        
        // Keep thread alive
        try {
            while (!Thread.currentThread().isInterrupted()) {
                Thread.sleep(1000);
            }
        } catch (InterruptedException e) {
            println("Server interrupted - shutting down...");
            Thread.currentThread().interrupt();
        }
    }
    
    /**
     * Start the HTTP server and register all endpoints.
     * This mirrors the plugin's startServer() method exactly.
     */
    private void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);
        
        // Use a cached thread pool for better performance with multiple concurrent requests
        server.setExecutor(Executors.newCachedThreadPool());
        
        // Get current program
        Program currentProgram = getCurrentProgram();
        
        // Register Meta Endpoints (these don't require a program)
        registerMetaEndpoints(server);
        
        // Register endpoints that don't require a program
        registerProjectEndpoints(server);
        new InstanceEndpoints(pluginState).registerEndpoints(server);
        
        // Register Resource Endpoints that require a program
        registerProgramDependentEndpoints(server, pluginState);
        
        // Register Root Endpoint (should be last to include links to all other endpoints)
        registerRootEndpoint(server);
        
        // Start server in background thread
        new Thread(() -> {
            server.start();
            println("HTTP server thread started on port " + port);
        }, "GhidraMCP-Headless-HTTP-Server").start();
    }
    
    /**
     * Register all endpoints that require a program to function.
     * This mirrors the plugin's implementation exactly.
     */
    private void registerProgramDependentEndpoints(HttpServer server, HeadlessPluginState pluginState) {
        println("Registering program-dependent endpoints. Programs will be checked at runtime.");
        
        Program currentProgram = getCurrentProgram();
        println("Current program at registration time: " + (currentProgram != null ? currentProgram.getName() : "none"));
        
        // Pass pluginState to all endpoints (provides abstraction over GUI/headless differences)
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
        
        println("Registered program-dependent endpoints. Programs will be checked at runtime.");
    }
    
    /**
     * Register meta endpoints that provide plugin information.
     * This mirrors the plugin's implementation exactly.
     */
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
                printerr("Error handling /plugin-version: " + e.getMessage());
            }
        });
        
        // Info endpoint
        server.createContext("/info", exchange -> {
            try {
                Map<String, Object> infoData = new HashMap<>();
                infoData.put("isBaseInstance", isBaseInstance);
                infoData.put("mode", "headless");
                
                Program program = getCurrentProgram();
                if (program != null) {
                    infoData.put("file", program.getName());
                    infoData.put("architecture", program.getLanguage().getLanguageID().getIdAsString());
                    infoData.put("processor", program.getLanguage().getProcessor().toString());
                    infoData.put("addressSize", program.getAddressFactory().getDefaultAddressSpace().getSize());
                    infoData.put("creationDate", program.getCreationDate());
                    infoData.put("executable", program.getExecutablePath());
                }
                
                // Note: No project info in headless mode (or very limited)
                infoData.put("project", "headless");
                
                // Add server details
                infoData.put("serverPort", port);
                infoData.put("serverStartTime", System.currentTimeMillis());
                infoData.put("instanceCount", activeInstances.size());
                
                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                   .success(true)
                   .result(infoData)
                   .addLink("self", "/info")
                   .addLink("root", "/")
                   .addLink("instances", "/instances");
                
                // Add program link if available
                if (program != null) {
                    builder.addLink("program", "/program");
                }
                
                HttpUtil.sendJsonResponse(exchange, builder.build(), 200, port);
            } catch (Exception e) {
                printerr("Error serving /info endpoint: " + e.getMessage());
                try { 
                    HttpUtil.sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR", port); 
                } catch (IOException ioEx) { 
                    printerr("Failed to send error for /info: " + ioEx.getMessage()); 
                }
            }
        });
    }
    
    /**
     * Register project-related endpoints.
     * In headless mode, project support is limited or not available.
     */
    private void registerProjectEndpoints(HttpServer server) {
        server.createContext("/projects", exchange -> {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    // Headless mode has limited/no project support
                    List<Map<String, String>> projects = new ArrayList<>();
                    
                    // Could potentially add current program as a "project"
                    Program program = getCurrentProgram();
                    if (program != null) {
                        Map<String, String> projInfo = new HashMap<>();
                        projInfo.put("name", "headless");
                        projInfo.put("location", program.getExecutablePath());
                        projInfo.put("mode", "headless");
                        projects.add(projInfo);
                    }
                    
                    ResponseBuilder builder = new ResponseBuilder(exchange, port)
                        .success(true)
                        .result(projects)
                        .addLink("self", "/projects");
                        
                    HttpUtil.sendJsonResponse(exchange, builder.build(), 200, port);
                } else if ("POST".equals(exchange.getRequestMethod())) {
                    HttpUtil.sendErrorResponse(exchange, 501, "Creating projects in headless mode is not supported", "NOT_IMPLEMENTED", port);
                } else {
                    HttpUtil.sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED", port);
                }
            } catch (Exception e) {
                printerr("Error serving /projects endpoint: " + e.getMessage());
                try { 
                    HttpUtil.sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR", port); 
                } catch (IOException ioEx) { 
                    printerr("Failed to send error for /projects: " + ioEx.getMessage()); 
                }
            }
        });
    }
    
    /**
     * Register root endpoint with HATEOAS links to all resources.
     * This mirrors the plugin's implementation exactly.
     */
    private void registerRootEndpoint(HttpServer server) {
        server.createContext("/", exchange -> {
            try {
                String path = exchange.getRequestURI().getPath();
                if (!path.equals("/")) {
                    // Not the root path, don't handle here
                    HttpUtil.sendErrorResponse(exchange, 404, "Endpoint not found: " + path, "ENDPOINT_NOT_FOUND", port);
                    return;
                }
                
                if (!"GET".equals(exchange.getRequestMethod())) {
                    HttpUtil.sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED", port);
                    return;
                }
                
                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .result(Map.of(
                        "message", "GhidraMCP API (Headless Mode)",
                        "version", ApiConstants.API_VERSION,
                        "mode", "headless"
                    ))
                    .addLink("self", "/")
                    .addLink("info", "/info")
                    .addLink("plugin-version", "/plugin-version")
                    .addLink("instances", "/instances")
                    .addLink("projects", "/projects");
                
                // Add program-dependent links if a program is available
                Program program = getCurrentProgram();
                if (program != null) {
                    builder
                           .addLink("program", "/program")
                           .addLink("functions", "/functions")
                           .addLink("variables", "/variables")
                           .addLink("classes", "/classes")
                           .addLink("symbols", "/symbols")
                           .addLink("namespaces", "/namespaces")
                           .addLink("data", "/data")
                           .addLink("segments", "/segments")
                           .addLink("memory", "/memory")
                           .addLink("xrefs", "/xrefs")
                           .addLink("analysis", "/analysis")
                           .addLink("address", "/address")
                           .addLink("function", "/function")
                           .addLink("datatypes", "/datatypes")
                           .addLink("equates", "/equates");
                }
                
                HttpUtil.sendJsonResponse(exchange, builder.build(), 200, port);
            } catch (Exception e) {
                printerr("Error serving / endpoint: " + e.getMessage());
                try { 
                    HttpUtil.sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR", port); 
                } catch (IOException ioEx) { 
                    printerr("Failed to send error for /: " + ioEx.getMessage()); 
                }
            }
        });
    }
    
    /**
     * Find an available port for the HTTP server.
     * Tries the requested port first, then searches for alternatives.
     */
    private int findAvailablePort(int requestedPort) {
        int maxAttempts = ApiConstants.MAX_PORT_ATTEMPTS;
        
        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            int candidate = requestedPort + attempt;
            if (!activeInstances.containsKey(candidate)) {
                try (ServerSocket s = new ServerSocket(candidate)) {
                    println("Found available port: " + candidate);
                    return candidate;
                } catch (IOException e) {
                    println("Port " + candidate + " is not available, trying next.");
                }
            } else {
                println("Port " + candidate + " already tracked as active instance.");
            }
        }
        
        String error = "Could not find an available port between " + requestedPort + 
                      " and " + (requestedPort + maxAttempts - 1);
        printerr(error);
        throw new RuntimeException(error);
    }
    
    /**
     * Clean up resources when shutting down.
     */
    private void cleanup() {
        println("Cleaning up GhidraMCP Headless Script...");
        
        if (server != null) {
            server.stop(0); // Stop immediately
            println("HTTP server stopped on port " + port);
        }
        
        if (pluginState != null) {
            pluginState.dispose();
        }
        
        activeInstances.remove(port);
        println("Cleanup complete.");
    }
    
    /**
     * Override cleanup to ensure proper shutdown.
     */
    @Override
    public void cleanup(boolean success) {
        cleanup();
        super.cleanup(success);
    }
}
