//Creates functions at addresses pointed to by a selected range of pointers
//@author mobilemutex
//@category Functions
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.symbol.SourceType;
import java.util.ArrayList;
import java.util.List;

public class CreateFunctionsFromPointers extends GhidraScript {

    @Override
    public void run() throws Exception {
        
        // Check if there's a current selection
        if (currentSelection == null || currentSelection.isEmpty()) {
            popup("Please select a range of memory containing pointers before running this script.");
            return;
        }
        
        // Get the memory object
        Memory memory = currentProgram.getMemory();
        
        // Get the address factory for creating addresses
        AddressFactory addressFactory = currentProgram.getAddressFactory();
        
        // Get the default address space (usually RAM)
        AddressSpace defaultSpace = addressFactory.getDefaultAddressSpace();
        
        // Determine pointer size based on the program's architecture
        int pointerSize = defaultSpace.getPointerSize();
        println("Detected pointer size: " + pointerSize + " bytes");
        
        // List to store valid target addresses
        List<Address> targetAddresses = new ArrayList<>();
        
        // Iterate through the selected address ranges
        AddressRangeIterator rangeIterator = currentSelection.getAddressRanges();
        
        while (rangeIterator.hasNext()) {
            AddressRange range = rangeIterator.next();
            Address currentAddr = range.getMinAddress();
            Address endAddr = range.getMaxAddress();
            
            println("Processing range: " + currentAddr + " to " + endAddr);
            
            // Process each pointer-sized chunk in the range
            while (currentAddr.compareTo(endAddr) <= 0) {
                
                // Check if we have enough bytes left for a complete pointer
                if (currentAddr.add(pointerSize - 1).compareTo(endAddr) > 0) {
                    break;
                }
                
                try {
                    // Read the pointer value from memory
                    long pointerValue;
                    
                    if (pointerSize == 4) {
                        // 32-bit pointer
                        pointerValue = memory.getInt(currentAddr) & 0xFFFFFFFFL;
                    } else if (pointerSize == 8) {
                        // 64-bit pointer
                        pointerValue = memory.getLong(currentAddr);
                    } else {
                        println("Unsupported pointer size: " + pointerSize);
                        return;
                    }
                    
                    // Create address from the pointer value
                    Address targetAddress = defaultSpace.getAddress(pointerValue);
                    
                    // Validate the target address
                    if (targetAddress != null && memory.contains(targetAddress)) {
                        // Check if the target address is in an executable memory block
                        MemoryBlock targetBlock = memory.getBlock(targetAddress);
                        if (targetBlock != null && targetBlock.isExecute()) {
                            targetAddresses.add(targetAddress);
                            println("Found valid pointer at " + currentAddr + " -> " + targetAddress);
                        } else {
                            println("Pointer at " + currentAddr + " points to non-executable memory: " + targetAddress);
                        }
                    } else {
                        println("Pointer at " + currentAddr + " contains invalid address: 0x" + Long.toHexString(pointerValue));
                    }
                    
                } catch (MemoryAccessException e) {
                    println("Memory access error at " + currentAddr + ": " + e.getMessage());
                } catch (Exception e) {
                    println("Error processing pointer at " + currentAddr + ": " + e.getMessage());
                }
                
                // Move to the next pointer
                currentAddr = currentAddr.add(pointerSize);
            }
        }
        
        if (targetAddresses.isEmpty()) {
            popup("No valid function pointers found in the selected range.");
            return;
        }
        
        // Ask user for confirmation
        boolean proceed = askYesNo("Create Functions", 
            "Found " + targetAddresses.size() + " valid function pointers.\n" +
            "Do you want to create functions at these addresses?");
        
        if (!proceed) {
            println("Operation cancelled by user.");
            return;
        }
        
        // Create functions at the target addresses
        int successCount = 0;
        int skipCount = 0;
        
        for (Address targetAddr : targetAddresses) {
            try {
                // Check if a function already exists at this address
                Function existingFunction = getFunctionAt(targetAddr);
                if (existingFunction != null) {
                    println("Function already exists at " + targetAddr + ": " + existingFunction.getName());
                    skipCount++;
                    continue;
                }
                
                // Create the function using CreateFunctionCmd
                CreateFunctionCmd createCmd = new CreateFunctionCmd(targetAddr);
                
                if (createCmd.applyTo(currentProgram)) {
                    Function newFunction = getFunctionAt(targetAddr);
                    if (newFunction != null) {
                        println("Successfully created function at " + targetAddr + ": " + newFunction.getName());
                        successCount++;
                    } else {
                        println("Function creation command succeeded but no function found at " + targetAddr);
                    }
                } else {
                    println("Failed to create function at " + targetAddr + ": " + createCmd.getStatusMsg());
                }
                
            } catch (Exception e) {
                println("Error creating function at " + targetAddr + ": " + e.getMessage());
            }
        }
        
        // Display summary
        String summary = "Function creation complete:\n" +
                        "- Successfully created: " + successCount + " functions\n" +
                        "- Skipped (already exist): " + skipCount + " functions\n" +
                        "- Total processed: " + targetAddresses.size() + " addresses";
        
        println(summary);
        popup(summary);
    }
}

