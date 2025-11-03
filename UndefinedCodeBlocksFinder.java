//
// Ghidra Script: UndefinedCodeBlocksFinder
// Purpose: Identifies and processes undefined LAB_ code blocks by finding
// memory references to them and creating functions from those references.
// Ghidra Version: 11.0.0+
// @author
// @category Search
// @keybinding
// @menupath Search.Find Undefined Code Functions
// @toolbar
//

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.framework.cmd.Command;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class UndefinedCodeBlocksFinder extends GhidraScript {

    // ========== USER CONFIGURABLE OPTIONS ==========
    
    /** Maximum search iterations to prevent infinite loops */
    private static final int MAX_SEARCH_ITERATIONS = 100;
    
    /** Size of each memory chunk to search (in bytes) */
    private static final int MEMORY_SEARCH_CHUNK_SIZE = 0x10000; // 64KB
    
    /** Maximum number of references to search for per LAB_ block */
    private static final int MAX_REFERENCES_PER_BLOCK = 500;
    
    /** Enable verbose output for debugging */
    private static final boolean VERBOSE_OUTPUT = true;
    
    /** Minimum address size for pointer search (in bytes) */
    private static final int POINTER_SIZE_BYTES = 4; // Change to 8 for 64-bit pointers
    
    /** Log file output enabled */
    private static final boolean LOG_TO_FILE = false;
    
    // ========== END USER CONFIGURABLE OPTIONS ==========
    
    private TaskMonitor taskMonitor;
    private int labBlocksFound = 0;
    private int referencesDiscovered = 0;
    private int functionsCreated = 0;
    private int referencesNotFound = 0;
    private Map<Address, Integer> labBlockAddresses;
    private StringBuilder logBuffer;
    
    @Override
    protected void run() throws Exception {
        // Initialize
        taskMonitor = new ConsoleTaskMonitor();
        labBlockAddresses = new HashMap<>();
        logBuffer = new StringBuilder();
        
        log("========================================");
        log("Undefined Code Function Finder");
        log("Ghidra Version: 11.0.0+");
        log("========================================");
        log("");
        
        try {
            // Step 1: Find all LAB_ code blocks
            if (!findUndefinedCodeBlocks()) {
                log("No undefined code blocks found.");
                return;
            }
            
            log("\n[*] Found " + labBlocksFound + " undefined code block(s)");
            
            // Step 2: Search for memory references to each LAB_ block
            if (!searchForReferences()) {
                log("Warning: Reference search encountered issues.");
            }
            
            log("\n[*] Discovered " + referencesDiscovered + " reference(s)");
            log("[*] LAB_ blocks with no references: " + referencesNotFound);
            
            // Step 3: Create functions from discovered references
            createFunctionsFromReferences();
            
            log("\n[*] Created " + functionsCreated + " function(s)");
            
        } catch (Exception e) {
            Msg.error(this, "Error during analysis: " + e.getMessage());
            log("ERROR: " + e.getMessage());
            e.printStackTrace();
        }
        
        log("");
        log("========================================");
        log("Analysis Complete");
        log("Summary:");
        log("  - LAB_ blocks found: " + labBlocksFound);
        log("  - References discovered: " + referencesDiscovered);
        log("  - Functions created: " + functionsCreated);
        log("  - Blocks without references: " + referencesNotFound);
        log("========================================");
    }
    
    /**
     * Step 1: Find all LAB_ code blocks that are not part of a defined function
     */
    private boolean findUndefinedCodeBlocks() throws Exception {
        log("\n[STEP 1] Scanning for undefined LAB_ code blocks...");
        
        try {
            Instruction instr = getFirstInstruction();
            
            while (instr != null && !monitor.isCancelled()) {
                Address addr = instr.getAddress();
                String label = getSymbolName(addr);
                
                // Check if this is a LAB_ block not in a defined function
                if (label != null && label.startsWith("LAB_")) {
                    if (currentProgram.getFunctionManager().getFunctionContaining(addr) == null) {
                        labBlockAddresses.put(addr, POINTER_SIZE_BYTES);
                        labBlocksFound++;
                        
                        if (VERBOSE_OUTPUT) {
                            log("  Found LAB_ block at: " + addr.toString() + " (" + label + ")");
                        }
                    }
                }
                
                instr = getNextInstruction(instr);
            }
            
        } catch (Exception e) {
            Msg.error(this, "Error finding LAB_ blocks: " + e.getMessage());
            log("ERROR finding LAB_ blocks: " + e.getMessage());
            return false;
        }
        
        return labBlocksFound > 0;
    }
    
    /**
     * Step 2: Search for memory references to LAB_ blocks
     */
    private boolean searchForReferences() throws Exception {
        log("\n[STEP 2] Searching for memory references...");
        
        for (Address labAddr : labBlockAddresses.keySet()) {
            if (monitor.isCancelled()) {
                break;
            }
            
            try {
                String hexValue = formatAddressAsHex(labAddr);
                log("\n  Searching for references to: " + labAddr.toString() + " (0x" + hexValue + ")");
                
                searchAndMarkReferences(labAddr);
                
            } catch (Exception e) {
                Msg.error(this, "Error searching for references to " + labAddr + ": " + e.getMessage());
                log("  ERROR searching for " + labAddr + ": " + e.getMessage());
                referencesNotFound++;
            }
        }
        
        return referencesDiscovered > 0 || referencesNotFound == 0;
    }
    
    /**
     * Search through memory for pointers to the given LAB_ address
     */
    private void searchAndMarkReferences(Address targetAddr) throws Exception {
        try {
            long targetValue = targetAddr.getOffset();
            int searchCount = 0;
            int maxIterations = MAX_SEARCH_ITERATIONS;
            
            // Search in different memory regions
            Address searchAddr = getMinAddress();
            
            while (searchAddr != null && !monitor.isCancelled() && searchCount < MAX_REFERENCES_PER_BLOCK) {
                try {
                    // Read potential pointer value from memory
                    byte[] pointerBytes = new byte[POINTER_SIZE_BYTES];
                    int bytesRead = getBytes(searchAddr, pointerBytes);
                    
                    if (bytesRead == POINTER_SIZE_BYTES) {
                        long pointerValue = bytesToLong(pointerBytes);
                        
                        // Check if this matches our target address
                        if (matchesAddress(pointerValue, targetValue)) {
                            referencesDiscovered++;
                            searchCount++;
                            
                            // Create pointer reference
                            try {
                                Address refAddr = getAddress(pointerValue);
                                createMemoryReference(searchAddr, refAddr);
                                
                                if (VERBOSE_OUTPUT) {
                                    log("    Found reference at: " + searchAddr.toString() + 
                                        " -> " + refAddr.toString());
                                }
                            } catch (Exception e) {
                                if (VERBOSE_OUTPUT) {
                                    log("    Could not create reference: " + e.getMessage());
                                }
                            }
                        }
                    }
                    
                    // Move to next address
                    try {
                        searchAddr = searchAddr.add(1);
                    } catch (Exception e) {
                        break; // End of memory space
                    }
                    
                } catch (Exception e) {
                    // Skip problematic addresses
                    try {
                        searchAddr = searchAddr.add(POINTER_SIZE_BYTES);
                    } catch (Exception ex) {
                        break;
                    }
                }
            }
            
            if (searchCount == 0) {
                referencesNotFound++;
                log("    No references found for " + targetAddr.toString());
            }
            
        } catch (Exception e) {
            Msg.error(this, "Error in searchAndMarkReferences: " + e.getMessage());
            throw e;
        }
    }
    
    /**
     * Step 3: Create functions from discovered references
     */
    private void createFunctionsFromReferences() throws Exception {
        log("\n[STEP 3] Creating functions from LAB_ blocks...");
        
        for (Address labAddr : labBlockAddresses.keySet()) {
            if (monitor.isCancelled()) {
                break;
            }
            
            try {
                // Check if function already exists
                if (currentProgram.getFunctionManager().getFunctionContaining(labAddr) != null) {
                    if (VERBOSE_OUTPUT) {
                        log("  Function already exists at: " + labAddr.toString());
                    }
                    continue;
                }
                
                // Create function using CreateFunctionCmd
                String functionName = generateFunctionName(labAddr);
                
                try {
                    CreateFunctionCmd cmd = new CreateFunctionCmd(labAddr);
                    
                    if (executeCommand(cmd)) {
                        functionsCreated++;
                        log("  Created function: " + functionName + " at " + labAddr.toString());
                    } else {
                        log("  Failed to create function at " + labAddr.toString());
                    }
                    
                } catch (Exception e) {
                    Msg.error(this, "Error creating function at " + labAddr + ": " + e.getMessage());
                    log("  ERROR creating function: " + e.getMessage());
                }
                
            } catch (Exception e) {
                Msg.error(this, "Error processing LAB_ block at " + labAddr + ": " + e.getMessage());
                log("  ERROR processing block: " + e.getMessage());
            }
        }
    }
    
    /**
     * Create a memory reference from source to target
     */
    private void createMemoryReference(Address fromAddr, Address toAddr) throws Exception {
        try {
            currentProgram.getReferenceManager().addMemoryReference(
                fromAddr,
                toAddr,
                RefType.DATA,
                SourceType.ANALYSIS,
                0
            );
        } catch (Exception e) {
            if (VERBOSE_OUTPUT) {
                log("    Could not add reference: " + e.getMessage());
            }
            // Continue on error
        }
    }
    
    /**
     * Get symbol name at address
     */
    private String getSymbolName(Address addr) {
        try {
            if (currentProgram.getSymbolTable().getSymbols(addr).length > 0) {
                return currentProgram.getSymbolTable().getSymbols(addr)[0].getName();
            }
        } catch (Exception e) {
            // Return null on error
        }
        return null;
    }
    
    /**
     * Format address as hex string
     */
    private String formatAddressAsHex(Address addr) {
        return String.format("%X", addr.getOffset());
    }
    
    /**
     * Convert bytes to long value (little-endian)
     */
    private long bytesToLong(byte[] bytes) {
        long value = 0;
        for (int i = 0; i < Math.min(bytes.length, 8); i++) {
            value |= (long)(bytes[i] & 0xFF) << (i * 8);
        }
        return value;
    }
    
    /**
     * Check if a long value matches a target address
     */
    private boolean matchesAddress(long pointerValue, long targetValue) {
        // Exact match
        if (pointerValue == targetValue) {
            return true;
        }
        
        // Check for address space variations (e.g., upper bits set differently)
        long mask = (POINTER_SIZE_BYTES == 8) ? 0xFFFFFFFFFFFFFFFL : 0xFFFFFFFFL;
        return (pointerValue & mask) == (targetValue & mask);
    }
    
    /**
     * Get bytes from memory at address
     */
    private int getBytes(Address addr, byte[] buffer) {
        try {
            return currentProgram.getMemory().getBytes(addr, buffer, 0, buffer.length);
        } catch (Exception e) {
            return 0;
        }
    }
    
    /**
     * Get first instruction in program
     */
    private Instruction getFirstInstruction() {
        try {
            return currentProgram.getListing().getInstructions(true).next();
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * Get next instruction
     */
    private Instruction getNextInstruction(Instruction instr) {
        try {
            Address next = instr.getAddress().add(instr.getLength());
            return currentProgram.getListing().getInstructionAt(next);
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * Get minimum address in memory
     */
    private Address getMinAddress() {
        try {
            return currentProgram.getMemory().getMinAddress();
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * Generate a function name for LAB_ block
     */
    private String generateFunctionName(Address addr) {
        String label = getSymbolName(addr);
        if (label != null) {
            return label;
        }
        return "FUN_" + String.format("%X", addr.getOffset()).toUpperCase();
    }
    
    /**
     * Execute a command on the program
     */
    private boolean executeCommand(Command<?> cmd) {
        try {
            return currentProgram.executeCommand(cmd);
        } catch (Exception e) {
            Msg.error(this, "Error executing command: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Log message to console and buffer
     */
    private void log(String message) {
        println(message);
        logBuffer.append(message).append("\n");
        
        if (LOG_TO_FILE) {
            try {
                // Optional: Write to file
                // Files.write(Paths.get("ghidra_undefined_code_analysis.log"), 
                //     logBuffer.toString().getBytes(), StandardOpenOption.CREATE);
            } catch (Exception e) {
                // Silently fail
            }
        }
    }
}
