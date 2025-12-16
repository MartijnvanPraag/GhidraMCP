package au.federation.ghidra;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

/**
 * Headless implementation of PluginState for use with GhidraScript.
 * This implementation delegates to the GhidraScript instance to access Ghidra resources.
 */
public class HeadlessPluginState implements PluginState {
    
    private final GhidraScript script;
    private Program currentProgram;
    private int port;
    private final ConsoleTaskMonitor monitor;
    
    /**
     * Create a headless plugin state wrapper.
     * 
     * @param script the GhidraScript instance
     * @param port the HTTP server port
     */
    public HeadlessPluginState(GhidraScript script, int port) {
        if (script == null) {
            throw new IllegalArgumentException("Script cannot be null");
        }
        this.script = script;
        this.port = port;
        this.currentProgram = script.getCurrentProgram();
        this.monitor = new ConsoleTaskMonitor();
    }
    
    @Override
    public Program getCurrentProgram() {
        // Always try to get from script first (most up-to-date)
        Program scriptProgram = script.getCurrentProgram();
        if (scriptProgram != null) {
            return scriptProgram;
        }
        // Fall back to stored program
        return currentProgram;
    }
    
    @Override
    public void setCurrentProgram(Program program) {
        this.currentProgram = program;
        // Note: We cannot set the program on GhidraScript directly
        // The script's current program is set when it's run
        // This field is for tracking purposes
        if (program != null) {
            println("Current program set to: " + program.getName());
        } else {
            println("Current program cleared");
        }
    }
    
    @Override
    public PluginTool getTool() {
        // No tool in headless mode
        return null;
    }
    
    @Override
    public boolean isHeadless() {
        return true;
    }
    
    @Override
    public void println(String message) {
        script.println("[GhidraMCP Headless] " + message);
        // Also print to console for systemd/docker logs
        System.out.println("[GhidraMCP Headless] " + message);
    }
    
    @Override
    public void printerr(String message) {
        script.printerr("[GhidraMCP Headless ERROR] " + message);
        System.err.println("[GhidraMCP Headless ERROR] " + message);
    }
    
    @Override
    public void printerr(String message, Throwable throwable) {
        script.printerr("[GhidraMCP Headless ERROR] " + message);
        System.err.println("[GhidraMCP Headless ERROR] " + message);
        if (throwable != null) {
            throwable.printStackTrace(System.err);
            // Also print to script error stream
            script.printerr("Exception: " + throwable.getClass().getName() + ": " + throwable.getMessage());
            for (StackTraceElement element : throwable.getStackTrace()) {
                script.printerr("  at " + element.toString());
            }
        }
    }
    
    @Override
    public TaskMonitor getMonitor() {
        return monitor;
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
        println("HeadlessPluginState disposing");
        
        // Clean up the monitor
        if (monitor != null) {
            monitor.clearCancelled();
        }
        
        // Note: Program cleanup is handled by the script framework
        // We don't close the program here
    }
    
    @Override
    public String getInstanceName() {
        return "Headless Script (Port " + port + ")";
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
