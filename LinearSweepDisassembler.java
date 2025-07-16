//Linear Sweep Disassembler for Ghidra
//This script performs linear sweep disassembly starting from a user-specified address
//Linear sweep disassembles instructions sequentially without following control flow
//@author mobilemutex
//@category Analysis
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.disassemble.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.CancelledException;

public class LinearSweepDisassembler extends GhidraScript {

    @Override
    public void run() throws Exception {
        
        // Get the current program
        Program program = getCurrentProgram();
        if (program == null) {
            println("No program is currently open.");
            return;
        }
        
        // Ask user for starting address
        Address startAddr = askAddress("Linear Sweep Disassembly", 
            "Enter the starting address for linear sweep disassembly:");
        
        if (startAddr == null) {
            println("No starting address provided. Exiting.");
            return;
        }
        
        // Ask user for the number of bytes to disassemble
        long numBytes = askLong("Linear Sweep Disassembly", 
            "Enter the number of bytes to disassemble (or 0 for entire memory block):");
        
        if (numBytes < 0) {
            println("Invalid number of bytes. Exiting.");
            return;
        }
        
        // Determine end address
        Address endAddr;
        if (numBytes == 0) {
            // Use the entire memory block
            MemoryBlock block = program.getMemory().getBlock(startAddr);
            if (block == null) {
                println("Starting address is not in a valid memory block.");
                return;
            }
            endAddr = block.getEnd();
        } else {
            try {
                endAddr = startAddr.add(numBytes - 1);
            } catch (AddressOutOfBoundsException e) {
                println("End address would be out of bounds.");
                return;
            }
        }
        
        // Validate memory range
        Memory memory = program.getMemory();
        if (!memory.contains(startAddr) || !memory.contains(endAddr)) {
            println("Address range is not entirely within program memory.");
            return;
        }
        
        // Create address set for the range
        AddressSet addressSet = new AddressSet(startAddr, endAddr);
        
        // Ask if user wants to clear existing instructions first
        boolean clearExisting = askYesNo("Clear Existing Instructions", 
            "Do you want to clear existing instructions in the target range first?");
        
        if (clearExisting) {
            clearInstructions(addressSet);
        }
        
        // Perform linear sweep disassembly
        performLinearSweep(program, startAddr, endAddr, monitor);
        
        println("Linear sweep disassembly completed.");
        println("Range: " + startAddr + " to " + endAddr);
        println("Total bytes processed: " + (endAddr.subtract(startAddr) + 1));
    }
    
    /**
     * Performs linear sweep disassembly from startAddr to endAddr
     */
    private void performLinearSweep(Program program, Address startAddr, Address endAddr, TaskMonitor monitor) 
            throws CancelledException {
        
        println("Starting linear sweep disassembly...");
        println("Start address: " + startAddr);
        println("End address: " + endAddr);
        
        // Get disassembler instance
        Disassembler disassembler = Disassembler.getDisassembler(program, monitor, null);
        
        Address currentAddr = startAddr;
        int instructionCount = 0;
        int errorCount = 0;
        
        while (currentAddr.compareTo(endAddr) <= 0) {
            
            // Check for cancellation
            if (monitor.isCancelled()) {
                throw new CancelledException();
            }
            
            // Update progress
            if (instructionCount % 100 == 0) {
                monitor.setMessage("Disassembling at " + currentAddr + " (instruction " + instructionCount + ")");
            }
            
            try {
                // Check if there's already an instruction at this address
                Instruction existingInstr = program.getListing().getInstructionAt(currentAddr);
                if (existingInstr != null) {
                    // Skip to next address after existing instruction
                    currentAddr = existingInstr.getMaxAddress().next();
                    continue;
                }
                
                // Check if we have enough memory for at least one byte
                if (!program.getMemory().contains(currentAddr)) {
                    println("Address " + currentAddr + " is not in memory. Stopping.");
                    break;
                }
                
                // Create a single-address set for disassembly
                AddressSet singleAddrSet = new AddressSet(currentAddr, currentAddr);
                
                // Attempt to disassemble at current address
                // Use doFollowFlow = false for true linear sweep behavior
                AddressSet disassembledSet = disassembler.disassemble(currentAddr, singleAddrSet, false);
                
                if (disassembledSet != null && !disassembledSet.isEmpty()) {
                    // Successfully disassembled an instruction
                    Instruction newInstr = program.getListing().getInstructionAt(currentAddr);
                    if (newInstr != null) {
                        instructionCount++;
                        // Move to the next byte after this instruction
                        currentAddr = newInstr.getMaxAddress().next();
                        
                        // Print progress every 50 instructions
                        if (instructionCount % 50 == 0) {
                            println("Disassembled " + instructionCount + " instructions. Current address: " + currentAddr);
                        }
                    } else {
                        // Disassembly reported success but no instruction was created
                        // Move to next byte
                        currentAddr = currentAddr.next();
                        errorCount++;
                    }
                } else {
                    // Failed to disassemble at this address
                    // In linear sweep, we just move to the next byte
                    currentAddr = currentAddr.next();
                    errorCount++;
                    
                    // Print occasional error messages
                    if (errorCount % 100 == 0) {
                        println("Warning: " + errorCount + " disassembly failures so far. Current address: " + currentAddr);
                    }
                }
                
            } catch (Exception e) {
                // Handle any exceptions during disassembly
                println("Error disassembling at " + currentAddr + ": " + e.getMessage());
                currentAddr = currentAddr.next();
                errorCount++;
            }
        }
        
        println("Linear sweep completed:");
        println("  Instructions created: " + instructionCount);
        println("  Disassembly failures: " + errorCount);
        println("  Final address: " + currentAddr);
    }
    
    /**
     * Clears existing instructions in the given address set
     */
    private void clearInstructions(AddressSet addressSet) {
        println("Clearing existing instructions in range...");
        
        Listing listing = currentProgram.getListing();
        InstructionIterator instrIter = listing.getInstructions(addressSet, true);
        
        int clearedCount = 0;
        while (instrIter.hasNext()) {
            Instruction instr = instrIter.next();
            try {
                listing.clearCodeUnits(instr.getMinAddress(), instr.getMaxAddress(), false);
                clearedCount++;
            } catch (Exception e) {
                println("Error clearing instruction at " + instr.getMinAddress() + ": " + e.getMessage());
            }
        }
        
        println("Cleared " + clearedCount + " existing instructions.");
    }
}

