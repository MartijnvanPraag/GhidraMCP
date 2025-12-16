package au.federation.ghidra;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * GUI implementation of PluginState for use with Plugin.
 * This implementation delegates to the plugin and tool to access Ghidra resources.
 */
public class GUIPluginState implements PluginState {
    
    private final Plugin plugin;
    private int port;
    
    /**
     * Create a GUI plugin state wrapper.
     * 
     * @param plugin the Plugin instance
     * @param port the HTTP server port
     */
    public GUIPluginState(Plugin plugin, int port) {
        if (plugin == null) {
            throw new IllegalArgumentException("Plugin cannot be null");
        }
        this.plugin = plugin;
        this.port = port;
    }
    
    @Override
    public Program getCurrentProgram() {
        try {
            PluginTool tool = getTool();
            if (tool != null) {
                ProgramManager programManager = tool.getService(ProgramManager.class);
                if (programManager != null) {
                    return programManager.getCurrentProgram();
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Error getting current program from tool", e);
        }
        return null;
    }
    
    @Override
    public void setCurrentProgram(Program program) {
        // In GUI mode, program management is handled by the GUI/ProgramManager
        // This is effectively a no-op, but we log it for debugging
        if (program != null) {
            Msg.info(this, "Program change requested in GUI mode: " + program.getName() + 
                          " (actual program is managed by GUI)");
        }
    }
    
    @Override
    public PluginTool getTool() {
        return plugin.getTool();
    }
    
    @Override
    public boolean isHeadless() {
        return false;
    }
    
    @Override
    public void println(String message) {
        Msg.info(this, message);
        // Also print to console for visibility
        System.out.println("[GhidraMCP GUI] " + message);
    }
    
    @Override
    public void printerr(String message) {
        Msg.error(this, message);
        System.err.println("[GhidraMCP GUI ERROR] " + message);
    }
    
    @Override
    public void printerr(String message, Throwable throwable) {
        Msg.error(this, message, throwable);
        System.err.println("[GhidraMCP GUI ERROR] " + message);
        if (throwable != null) {
            throwable.printStackTrace(System.err);
        }
    }
    
    @Override
    public TaskMonitor getMonitor() {
        // In GUI mode, we could potentially use a GUI-aware monitor
        // For now, return a simple adapter that doesn't show progress
        return new TaskMonitorAdapter(true);
    }
    
    @Override
    public DecompInterface createDecompiler() {
        Program program = getCurrentProgram();
        if (program == null) {
            throw new IllegalStateException("Cannot create decompiler without a current program");
        }
        
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(program);
        return decompiler;
    }
    
    @Override
    public void dispose() {
        // GUI mode cleanup
        // The plugin framework handles most cleanup
        Msg.info(this, "GUIPluginState disposing");
    }
    
    @Override
    public String getInstanceName() {
        return "GUI Plugin (Port " + port + ")";
    }
    
    @Override
    public int getPort() {
        return port;
    }
    
    @Override
    public void setPort(int port) {
        this.port = port;
    }
}
