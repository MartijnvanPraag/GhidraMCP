package au.federation.ghidra;

import ghidra.app.decompiler.DecompInterface;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Abstraction interface for GhidraMCP plugin state.
 * Provides a unified interface for accessing Ghidra resources in both
 * GUI mode (via ProgramPlugin) and headless mode (via GhidraScript).
 * 
 * This abstraction allows all endpoint classes to work identically in both
 * GUI and headless modes without modification.
 */
public interface PluginState {
    
    /**
     * Get the current program.
     * In GUI mode, this returns the program from ProgramManager.
     * In headless mode, this returns the script's current program.
     * 
     * @return the current program, or null if no program is loaded
     */
    Program getCurrentProgram();
    
    /**
     * Set the current program (primarily for headless mode).
     * In GUI mode, this may be a no-op as program management is handled by the GUI.
     * In headless mode, this sets the script's active program.
     * 
     * @param program the program to set as current
     */
    void setCurrentProgram(Program program);
    
    /**
     * Get the plugin tool (GUI mode only).
     * In GUI mode, this returns the PluginTool instance.
     * In headless mode, this returns null.
     * 
     * @return the PluginTool, or null in headless mode
     */
    PluginTool getTool();
    
    /**
     * Check if running in headless mode.
     * 
     * @return true if running in headless mode, false if running in GUI mode
     */
    boolean isHeadless();
    
    /**
     * Print a message to the console/log.
     * In GUI mode, this uses Msg.info().
     * In headless mode, this uses println() or printerr().
     * 
     * @param message the message to print
     */
    void println(String message);
    
    /**
     * Print an error message to the console/log.
     * In GUI mode, this uses Msg.error().
     * In headless mode, this uses printerr().
     * 
     * @param message the error message to print
     */
    void printerr(String message);
    
    /**
     * Print an error message with exception to the console/log.
     * In GUI mode, this uses Msg.error().
     * In headless mode, this uses printerr() with exception details.
     * 
     * @param message the error message to print
     * @param throwable the exception/throwable
     */
    void printerr(String message, Throwable throwable);
    
    /**
     * Get a task monitor for long-running operations.
     * In GUI mode, this may return a GUI-aware monitor.
     * In headless mode, this returns ConsoleTaskMonitor.
     * 
     * @return a TaskMonitor instance
     */
    TaskMonitor getMonitor();
    
    /**
     * Create a decompiler interface for decompiling functions.
     * This handles initialization and disposal of the decompiler.
     * 
     * @return a configured DecompInterface instance
     */
    DecompInterface createDecompiler();
    
    /**
     * Dispose of resources when the plugin/script is shutting down.
     * In GUI mode, this may dispose of GUI resources.
     * In headless mode, this may clean up temporary files or programs.
     */
    void dispose();
    
    /**
     * Get the name/identifier for this instance.
     * This is useful for logging and debugging.
     * 
     * @return the instance name (e.g., "GUI Plugin" or "Headless Script")
     */
    String getInstanceName();
    
    /**
     * Get the port number for the HTTP server.
     * 
     * @return the HTTP server port
     */
    int getPort();
    
    /**
     * Set the port number for the HTTP server.
     * 
     * @param port the HTTP server port
     */
    void setPort(int port);
}
