package au.federation.ghidra.endpoints;

    import com.google.gson.JsonObject;
    import com.sun.net.httpserver.HttpExchange;
    import com.sun.net.httpserver.HttpServer;
    import au.federation.ghidra.api.ResponseBuilder;
    import au.federation.ghidra.GhidraMCPPlugin; // Need access to activeInstances
    import au.federation.ghidra.GhidraMCPHeadlessScript; // Need access for headless mode
    import ghidra.program.model.listing.Program;
    import ghidra.util.Msg;

    import java.io.IOException;
    import java.util.*;

    public class InstanceEndpoints extends AbstractEndpoint {

        // Support both Plugin and Headless Script instances
        // Note: activeInstances is accessed from GhidraMCPPlugin.activeInstances and GhidraMCPHeadlessScript.activeInstances

        // Updated constructor to accept PluginState
        public InstanceEndpoints(au.federation.ghidra.PluginState pluginState) {
             super(pluginState); // Call super constructor with PluginState
        }

    @Override
    public void registerEndpoints(HttpServer server) {
        server.createContext("/instances", this::handleInstances);
        server.createContext("/registerInstance", this::handleRegisterInstance);
        server.createContext("/unregisterInstance", this::handleUnregisterInstance);
    }
    
    @Override
    protected boolean requiresProgram() {
        // This endpoint doesn't require a program to function
        return false;
    }
    
    /**
     * Helper to determine if an instance is a base instance.
     * Supports both GhidraMCPPlugin and GhidraMCPHeadlessScript instances.
     */
    private boolean isBaseInstance(Object instance) {
        if (instance instanceof GhidraMCPPlugin) {
            return ((GhidraMCPPlugin) instance).isBaseInstance();
        } else if (instance instanceof GhidraMCPHeadlessScript) {
            // Headless scripts don't have isBaseInstance method exposed
            // Assume base if on default port
            return false; // TODO: Add isBaseInstance to headless script if needed
        }
        return false;
    }
    
    /**
     * Helper to get the current program from an instance.
     * Supports both GhidraMCPPlugin and GhidraMCPHeadlessScript instances.
     */
    private Program getProgramFromInstance(Object instance) {
        if (instance instanceof GhidraMCPPlugin) {
            return ((GhidraMCPPlugin) instance).getCurrentProgram();
        } else if (instance instanceof GhidraMCPHeadlessScript) {
            return ((GhidraMCPHeadlessScript) instance).getCurrentProgram();
        }
        return null;
    }

        private void handleInstances(HttpExchange exchange) throws IOException {
            try {
                List<Map<String, Object>> instanceData = new ArrayList<>();
                
                // Access the static activeInstances map from both plugin and script
                Map<Integer, Object> activeInstances = new HashMap<>();
                activeInstances.putAll(GhidraMCPPlugin.activeInstances);
                activeInstances.putAll(GhidraMCPHeadlessScript.activeInstances);
                
                // Iterate over all active instances
                for (Map.Entry<Integer, Object> entry : activeInstances.entrySet()) {
                    Map<String, Object> instance = new HashMap<>();
                    int instancePort = entry.getKey();
                    Object instanceObj = entry.getValue();
                    
                    instance.put("port", instancePort);
                    instance.put("url", "http://localhost:" + instancePort);
                    
                    // Determine instance type
                    String instanceType = "unknown";
                    if (isBaseInstance(instanceObj)) {
                        instanceType = "base";
                    } else {
                        instanceType = "standard";
                    }
                    
                    // Add mode info
                    if (instanceObj instanceof GhidraMCPPlugin) {
                        instance.put("mode", "gui");
                    } else if (instanceObj instanceof GhidraMCPHeadlessScript) {
                        instance.put("mode", "headless");
                    } else {
                        instance.put("mode", "unknown");
                    }
                    
                    instance.put("type", instanceType);
                    
                    // Get program info if available
                    Program program = getProgramFromInstance(instanceObj);
                    if (program != null) {
                        instance.put("project", program.getDomainFile().getParent().getName());
                        instance.put("file", program.getName());
                    } else {
                        instance.put("project", "");
                        instance.put("file", "");
                    }
                    
                    // Add HATEOAS links for each instance
                    Map<String, Object> links = new HashMap<>();
                    
                    // Self link for this instance
                    Map<String, String> selfLink = new HashMap<>();
                    selfLink.put("href", "/instances/" + instancePort);
                    links.put("self", selfLink);
                    
                    // Info link for this instance
                    Map<String, String> infoLink = new HashMap<>();
                    infoLink.put("href", "http://localhost:" + instancePort + "/info");
                    links.put("info", infoLink);
                    
                    // Connect link
                    Map<String, String> connectLink = new HashMap<>();
                    connectLink.put("href", "http://localhost:" + instancePort);
                    links.put("connect", connectLink);
                    
                    // Add links to object
                    instance.put("_links", links);
                    
                    instanceData.add(instance);
                }
                
                // Build response with HATEOAS links
                ResponseBuilder builder = new ResponseBuilder(exchange, getPort())
                    .success(true)
                    .result(instanceData);
                
                // Add HATEOAS links
                builder.addLink("self", "/instances");
                builder.addLink("register", "/registerInstance", "POST");
                builder.addLink("unregister", "/unregisterInstance", "POST");
                builder.addLink("programs", "/programs");
                
                sendJsonResponse(exchange, builder.build(), 200);
            } catch (Exception e) {
                Msg.error(this, "Error in /instances endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        }

        private void handleRegisterInstance(HttpExchange exchange) throws IOException {
             try {
                Map<String, String> params = parseJsonPostParams(exchange);
                int regPort = parseIntOrDefault(params.get("port"), 0);
                if (regPort > 0) {
                     // Logic to actually register/track the instance should happen elsewhere (e.g., main plugin or dedicated manager)
                     sendSuccessResponse(exchange, Map.of("message", "Instance registration request received for port " + regPort)); // Use helper
                } else {
                     sendErrorResponse(exchange, 400, "Invalid or missing port number"); // Use helper
                }
            } catch (IOException e) {
                 Msg.error(this, "Error parsing POST params for registerInstance", e);
                 sendErrorResponse(exchange, 400, "Invalid request body: " + e.getMessage(), "INVALID_REQUEST"); // Use helper
            } catch (Exception e) {
                Msg.error(this, "Error in /registerInstance", e);
                 sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR"); // Use helper
            }
        }

        private void handleUnregisterInstance(HttpExchange exchange) throws IOException {
            try {
                Map<String, String> params = parseJsonPostParams(exchange);
                int unregPort = parseIntOrDefault(params.get("port"), 0);
                
                // Try to remove from both maps
                boolean removed = false;
                if (GhidraMCPPlugin.activeInstances.containsKey(unregPort)) {
                    GhidraMCPPlugin.activeInstances.remove(unregPort);
                    removed = true;
                }
                if (GhidraMCPHeadlessScript.activeInstances.containsKey(unregPort)) {
                    GhidraMCPHeadlessScript.activeInstances.remove(unregPort);
                    removed = true;
                }
                
                if (removed) {
                     sendSuccessResponse(exchange, Map.of("message", "Instance unregistered for port " + unregPort)); // Use helper
                } else {
                     sendErrorResponse(exchange, 404, "No instance found on port " + unregPort, "RESOURCE_NOT_FOUND"); // Use helper
                }
             } catch (IOException e) {
                 Msg.error(this, "Error parsing POST params for unregisterInstance", e);
                 sendErrorResponse(exchange, 400, "Invalid request body: " + e.getMessage(), "INVALID_REQUEST"); // Use helper
            } catch (Exception e) {
                Msg.error(this, "Error in /unregisterInstance", e);
                 sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR"); // Use helper
            }
        }


        // --- Helper Methods Removed (Inherited or internal logic adjusted) ---
        
        // parseIntOrDefault is inherited from AbstractEndpoint
    }

