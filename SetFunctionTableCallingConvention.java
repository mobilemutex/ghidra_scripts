//Changes the calling convention of all functions referenced by a selected function table to thiscall.
//Useful for C++ virtual function tables and other object-oriented function tables.
//Compatible with Ghidra 11.4 and later.
//@author mobilemutex
//@category Data Types
//@keybinding 
//@menupath Tools.Data Types.Set Function Table Calling Convention
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import java.util.*;

public class SetFunctionTableCallingConvention extends GhidraScript {
    
    // Available calling conventions - can be modified as needed
    private static final String[] AVAILABLE_CONVENTIONS = {
        "thiscall", "cdecl", "stdcall", "fastcall", "vectorcall", "__cdecl", "__stdcall", "__fastcall"
    };
    
    private static final String DEFAULT_CONVENTION = "thiscall";
    
    @Override
    public void run() throws Exception {
        // Validate that we have a selection
        if (currentSelection == null || currentSelection.isEmpty()) {
            popup("Please select a function table data structure before running this script.\\n" +
                  "The selection should contain a properly typed function table created by " +
                  "the CreateFunctionTableDataType script.");
            return;
        }
        
        println("Starting Function Table Calling Convention Update...");
        
        // Get program components
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Memory memory = currentProgram.getMemory();
        int pointerSize = currentProgram.getDefaultPointerSize();
        
        try {
            // Step 1: Get calling convention from user
            String targetConvention = getCallingConventionFromUser();
            if (targetConvention == null) {
                println("Operation cancelled by user");
                return;
            }
            
            println("Target calling convention: " + targetConvention);
            
            // Step 2: Analyze the selected region to find function tables
            List<FunctionTableInfo> functionTables = analyzeFunctionTables(memory, pointerSize);
            
            if (functionTables.isEmpty()) {
                popup("No function tables found in the selected region.\\n" +
                      "Please ensure you have selected a properly typed function table structure.");
                return;
            }
            
            println("Found " + functionTables.size() + " function table(s) in selection");
            
            // Step 3: Process each function table
            int totalFunctionsProcessed = 0;
            int totalFunctionsUpdated = 0;
            
            for (FunctionTableInfo tableInfo : functionTables) {
                println("\\nProcessing table at " + tableInfo.address + " (" + tableInfo.tableName + ")");
                
                ConversionResult result = updateTableCallingConventions(
                    tableInfo, targetConvention, funcMgr, dtm, memory, pointerSize);
                
                totalFunctionsProcessed += result.functionsProcessed;
                totalFunctionsUpdated += result.functionsUpdated;
                
                println("Table " + tableInfo.tableName + ": " + result.functionsUpdated + 
                       " of " + result.functionsProcessed + " functions updated");
            }
            
            // Step 4: Report results
            String message = "Calling convention update completed!\\n" +
                           "Tables processed: " + functionTables.size() + "\\n" +
                           "Functions processed: " + totalFunctionsProcessed + "\\n" +
                           "Functions updated: " + totalFunctionsUpdated + "\\n" +
                           "Target convention: " + targetConvention;
            
            println("\\n" + message.replace("\\n", "\\n"));
            popup(message);
            
        } catch (Exception e) {
            printerr("Error updating calling conventions: " + e.getMessage());
            e.printStackTrace();
            popup("Error: " + e.getMessage());
        }
    }
    
    /**
     * Gets the target calling convention from the user
     */
    private String getCallingConventionFromUser() {
        // Create choice list with available conventions
        List<String> choices = new ArrayList<>();
        for (String convention : AVAILABLE_CONVENTIONS) {
            choices.add(convention);
        }
        
        // Ask user to choose
        String choice = askChoice("Select Calling Convention", 
                                "Choose the calling convention to apply to all functions in the table:",
                                choices, DEFAULT_CONVENTION);
        
        return choice;
    }
    
    /**
     * Analyzes the selected region to find function table structures
     */
    private List<FunctionTableInfo> analyzeFunctionTables(Memory memory, int pointerSize) {
        List<FunctionTableInfo> tables = new ArrayList<>();
        
        // Get all data in the selected region
        Listing listing = currentProgram.getListing();
        
        for (AddressRange range : currentSelection) {
            DataIterator dataIter = listing.getDefinedData(range, true);
            
            while (dataIter.hasNext()) {
                Data data = dataIter.next();
                DataType dataType = data.getDataType();
                
                if (dataType instanceof StructureDataType) {
                    StructureDataType struct = (StructureDataType) dataType;
                    
                    if (isFunctionTable(struct)) {
                        FunctionTableInfo tableInfo = new FunctionTableInfo();
                        tableInfo.address = data.getAddress();
                        tableInfo.structure = struct;
                        tableInfo.tableName = struct.getName();
                        tableInfo.functionAddresses = extractFunctionAddresses(
                            struct, data.getAddress(), memory, pointerSize);
                        
                        tables.add(tableInfo);
                        println("Found function table: " + tableInfo.tableName + 
                               " with " + tableInfo.functionAddresses.size() + " functions");
                    }
                }
            }
        }
        
        return tables;
    }
    
    /**
     * Determines if a structure data type is a function table
     */
    private boolean isFunctionTable(StructureDataType struct) {
        DataTypeComponent[] components = struct.getDefinedComponents();
        if (components.length == 0) {
            return false;
        }
        
        int functionPointerCount = 0;
        for (DataTypeComponent component : components) {
            DataType fieldType = component.getDataType();
            
            if (fieldType instanceof PointerDataType) {
                PointerDataType ptr = (PointerDataType) fieldType;
                DataType referencedType = ptr.getDataType();
                
                if (referencedType instanceof FunctionDefinitionDataType) {
                    functionPointerCount++;
                }
            }
        }
        
        // Consider it a function table if most fields are function pointers
        return functionPointerCount >= components.length * 0.5;
    }
    
    /**
     * Extracts function addresses from a function table structure
     */
    private List<Address> extractFunctionAddresses(StructureDataType struct, Address tableAddr, 
            Memory memory, int pointerSize) {
        List<Address> addresses = new ArrayList<>();
        DataTypeComponent[] components = struct.getDefinedComponents();
        
        for (DataTypeComponent component : components) {
            DataType fieldType = component.getDataType();
            
            if (fieldType instanceof PointerDataType) {
                PointerDataType ptr = (PointerDataType) fieldType;
                DataType referencedType = ptr.getDataType();
                
                if (referencedType instanceof FunctionDefinitionDataType) {
                    Address fieldAddr = tableAddr.add(component.getOffset());
                    
                    try {
                        // Read pointer value
                        long pointerValue;
                        if (pointerSize == 8) {
                            pointerValue = memory.getLong(fieldAddr);
                        } else if (pointerSize == 4) {
                            pointerValue = memory.getInt(fieldAddr) & 0xFFFFFFFFL;
                        } else if (pointerSize == 2) {
                            pointerValue = memory.getShort(fieldAddr) & 0xFFFFL;
                        } else {
                            continue;
                        }
                        
                        // Convert to address
                        Address targetAddr = currentProgram.getAddressFactory()
                            .getDefaultAddressSpace().getAddress(pointerValue);
                        
                        if (memory.contains(targetAddr)) {
                            addresses.add(targetAddr);
                        }
                        
                    } catch (MemoryAccessException e) {
                        println("Memory access error at " + fieldAddr + ": " + e.getMessage());
                    }
                }
            }
        }
        
        return addresses;
    }
    
    /**
     * Updates calling conventions for all functions in a table
     */
    private ConversionResult updateTableCallingConventions(FunctionTableInfo tableInfo, 
            String targetConvention, FunctionManager funcMgr, DataTypeManager dtm, 
            Memory memory, int pointerSize) throws Exception {
        
        ConversionResult result = new ConversionResult();
        Map<String, FunctionDefinitionDataType> updatedDefs = new HashMap<>();
        
        // Process each function address
        DataTypeComponent[] components = tableInfo.structure.getDefinedComponents();
        
        for (int i = 0; i < Math.min(components.length, tableInfo.functionAddresses.size()); i++) {
            Address funcAddr = tableInfo.functionAddresses.get(i);
            DataTypeComponent component = components[i];
            
            result.functionsProcessed++;
            
            // Get the function at this address
            Function func = funcMgr.getFunctionAt(funcAddr);
            if (func == null) {
                println("No function found at " + funcAddr + ", skipping");
                continue;
            }
            
            String currentConvention = func.getCallingConventionName();
            
            // Check if update is needed
            if (targetConvention.equals(currentConvention)) {
                println("Function " + func.getName() + " already uses " + targetConvention);
                continue;
            }
            
            // Update the function's calling convention
            try {
                func.setCallingConvention(targetConvention);
                result.functionsUpdated++;
                
                println("Updated " + func.getName() + " from " + currentConvention + 
                       " to " + targetConvention);
                
                // Update the corresponding function definition data type
                DataType fieldType = component.getDataType();
                if (fieldType instanceof PointerDataType) {
                    PointerDataType ptr = (PointerDataType) fieldType;
                    DataType referencedType = ptr.getDataType();
                    
                    if (referencedType instanceof FunctionDefinitionDataType) {
                        FunctionDefinitionDataType funcDef = (FunctionDefinitionDataType) referencedType;
                        
                        // Create updated function definition
                        FunctionDefinitionDataType updatedDef = createUpdatedFunctionDefinition(
                            func, funcDef, targetConvention, dtm);
                        
                        if (updatedDef != null) {
                            updatedDefs.put(component.getFieldName(), updatedDef);
                        }
                    }
                }
                
            } catch (InvalidInputException e) {
                printerr("Failed to update calling convention for " + func.getName() + 
                        ": " + e.getMessage());
            }
        }
        
        // If we have updated function definitions, rebuild the table structure
        if (!updatedDefs.isEmpty()) {
            try {
                rebuildTableStructure(tableInfo, updatedDefs, dtm, pointerSize);
                println("Rebuilt table structure with updated function definitions");
            } catch (Exception e) {
                printerr("Failed to rebuild table structure: " + e.getMessage());
            }
        }
        
        return result;
    }
    
    /**
     * Creates an updated function definition with new calling convention
     */
    private FunctionDefinitionDataType createUpdatedFunctionDefinition(Function func, 
            FunctionDefinitionDataType originalDef, String newConvention, DataTypeManager dtm) 
            throws DuplicateNameException, InvalidInputException {
        
        FunctionSignature signature = func.getSignature();
        
        // Create new function definition with updated calling convention
        String defName = originalDef.getName();
        FunctionDefinitionDataType updatedDef = new FunctionDefinitionDataType(defName);
        
        updatedDef.setReturnType(signature.getReturnType());
        updatedDef.setArguments(signature.getArguments());
        updatedDef.setCallingConvention(newConvention);
        updatedDef.setVarArgs(signature.hasVarArgs());
        
        // Add to data type manager, replacing the old definition
        DataType resolvedDef = dtm.addDataType(updatedDef, DataTypeConflictHandler.REPLACE_HANDLER);
        
        if (resolvedDef instanceof FunctionDefinitionDataType) {
            return (FunctionDefinitionDataType) resolvedDef;
        }
        
        return null;
    }
    
    /**
     * Rebuilds a table structure with updated function definitions
     */
    private void rebuildTableStructure(FunctionTableInfo tableInfo, 
            Map<String, FunctionDefinitionDataType> updatedDefs, DataTypeManager dtm, 
            int pointerSize) throws Exception {
        
        StructureDataType originalTable = tableInfo.structure;
        
        // Create new structure with same name
        StructureDataType newTable = new StructureDataType(originalTable.getName(), 0);
        
        // Copy all components, updating the ones that changed
        DataTypeComponent[] components = originalTable.getDefinedComponents();
        
        for (DataTypeComponent component : components) {
            String fieldName = component.getFieldName();
            DataType fieldType = component.getDataType();
            String comment = component.getComment();
            
            // Check if this field needs updating
            if (updatedDefs.containsKey(fieldName)) {
                FunctionDefinitionDataType updatedDef = updatedDefs.get(fieldName);
                PointerDataType updatedPtr = new PointerDataType(updatedDef, pointerSize);
                newTable.add(updatedPtr, fieldName, comment);
            } else {
                // Keep original field
                newTable.add(fieldType, fieldName, comment);
            }
        }
        
        // Add updated structure to data type manager
        DataType resolvedTable = dtm.addDataType(newTable, DataTypeConflictHandler.REPLACE_HANDLER);
        
        // Apply the updated table to memory
        if (resolvedTable instanceof StructureDataType) {
            clearListing(tableInfo.address, tableInfo.address.add(originalTable.getLength() - 1));
            createData(tableInfo.address, resolvedTable);
        }
    }
    
    /**
     * Information about a function table found in the selection
     */
    private static class FunctionTableInfo {
        Address address;
        StructureDataType structure;
        String tableName;
        List<Address> functionAddresses;
    }
    
    /**
     * Result of calling convention conversion operation
     */
    private static class ConversionResult {
        int functionsProcessed = 0;
        int functionsUpdated = 0;
    }
}

