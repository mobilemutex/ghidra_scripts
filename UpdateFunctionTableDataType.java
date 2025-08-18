//Updates existing function table data types when function definitions change.
//Detects changes in function signatures and rebuilds function table structures accordingly.
//Compatible with Ghidra 11.4 and later.
//@author mobilemutex
//@category Data Types
//@keybinding 
//@menupath Tools.Data Types.Update Function Table Data Type
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import java.util.*;

public class UpdateFunctionTableDataType extends GhidraScript {
    
    private static final String FUNCTION_TABLE_SUFFIX = "FunctionTable";
    private static final String FUNCTION_DEF_SUFFIX = "_def";
    
    @Override
    public void run() throws Exception {
        println("Starting Function Table Data Type Update...");
        
        // Get program components
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Memory memory = currentProgram.getMemory();
        int pointerSize = currentProgram.getDefaultPointerSize();
        
        try {
            // Step 1: Find all function table data types
            List<StructureDataType> functionTables = findFunctionTableDataTypes(dtm);
            
            if (functionTables.isEmpty()) {
                popup("No function table data types found in this program.\\n" +
                      "Please create function tables first using the CreateFunctionTableDataType script.");
                return;
            }
            
            println("Found " + functionTables.size() + " function table data types");
            
            // Step 2: Process each function table
            int updatedTables = 0;
            int totalUpdates = 0;
            
            for (StructureDataType table : functionTables) {
                println("\\nProcessing table: " + table.getName());
                
                UpdateResult result = updateFunctionTable(table, dtm, funcMgr, memory, pointerSize);
                
                if (result.updatesApplied > 0) {
                    updatedTables++;
                    totalUpdates += result.updatesApplied;
                    println("Updated " + result.updatesApplied + " function definitions in " + table.getName());
                } else {
                    println("No updates needed for " + table.getName());
                }
            }
            
            // Step 3: Report results
            String message = "Function table update completed!\\n" +
                           "Tables processed: " + functionTables.size() + "\\n" +
                           "Tables updated: " + updatedTables + "\\n" +
                           "Total function definitions updated: " + totalUpdates;
            
            println("\\n" + message.replace("\\n", "\\n"));
            popup(message);
            
        } catch (Exception e) {
            printerr("Error updating function table data types: " + e.getMessage());
            e.printStackTrace();
            popup("Error: " + e.getMessage());
        }
    }
    
    /**
     * Finds all function table data types in the program
     */
    private List<StructureDataType> findFunctionTableDataTypes(DataTypeManager dtm) {
        List<StructureDataType> functionTables = new ArrayList<>();
        
        // Iterate through all data types
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            
            if (dt instanceof StructureDataType) {
                StructureDataType struct = (StructureDataType) dt;
                
                // Check if this looks like a function table
                if (isFunctionTable(struct)) {
                    functionTables.add(struct);
                    println("Found function table: " + struct.getName());
                }
            }
        }
        
        return functionTables;
    }
    
    /**
     * Determines if a structure data type is a function table
     */
    private boolean isFunctionTable(StructureDataType struct) {
        // Check name pattern
        String name = struct.getName();
        if (name.contains(FUNCTION_TABLE_SUFFIX)) {
            return true;
        }
        
        // Check if all fields are function pointers
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
        return functionPointerCount >= components.length * 0.7;
    }
    
    /**
     * Updates a single function table data type
     */
    private UpdateResult updateFunctionTable(StructureDataType table, DataTypeManager dtm, 
            FunctionManager funcMgr, Memory memory, int pointerSize) throws Exception {
        
        UpdateResult result = new UpdateResult();
        
        // Find where this table is used in memory
        List<Address> tableLocations = findTableUsageLocations(table);
        
        if (tableLocations.isEmpty()) {
            println("Warning: No memory locations found for table " + table.getName());
            return result;
        }
        
        // For each location, extract function addresses and check for updates
        for (Address tableAddr : tableLocations) {
            List<Address> functionAddresses = extractFunctionAddressesFromTable(
                table, tableAddr, memory, pointerSize);
            
            if (functionAddresses.isEmpty()) {
                continue;
            }
            
            // Check each function for signature changes
            DataTypeComponent[] components = table.getDefinedComponents();
            Map<String, FunctionDefinitionDataType> updatedDefs = new HashMap<>();
            
            for (int i = 0; i < Math.min(components.length, functionAddresses.size()); i++) {
                DataTypeComponent component = components[i];
                Address funcAddr = functionAddresses.get(i);
                
                // Get current function signature
                Function currentFunc = funcMgr.getFunctionAt(funcAddr);
                if (currentFunc == null) {
                    continue;
                }
                
                // Get stored function definition
                DataType fieldType = component.getDataType();
                if (!(fieldType instanceof PointerDataType)) {
                    continue;
                }
                
                PointerDataType ptr = (PointerDataType) fieldType;
                DataType referencedType = ptr.getDataType();
                
                if (!(referencedType instanceof FunctionDefinitionDataType)) {
                    continue;
                }
                
                FunctionDefinitionDataType storedDef = (FunctionDefinitionDataType) referencedType;
                
                // Compare signatures
                if (signatureChanged(currentFunc, storedDef)) {
                    println("Function signature changed: " + currentFunc.getName() + " at " + funcAddr);
                    
                    // Create updated function definition
                    FunctionDefinitionDataType updatedDef = createUpdatedFunctionDefinition(
                        currentFunc, storedDef, dtm);
                    
                    if (updatedDef != null) {
                        updatedDefs.put(component.getFieldName(), updatedDef);
                        result.updatesApplied++;
                    }
                }
            }
            
            // If we have updates, rebuild the table structure
            if (!updatedDefs.isEmpty()) {
                StructureDataType updatedTable = rebuildTableStructure(
                    table, updatedDefs, dtm, pointerSize);
                
                // Apply the updated table to memory
                applyUpdatedTable(tableAddr, table, updatedTable);
                result.tablesRebuilt++;
            }
        }
        
        return result;
    }
    
    /**
     * Finds memory locations where a table data type is used
     */
    private List<Address> findTableUsageLocations(StructureDataType table) {
        List<Address> locations = new ArrayList<>();
        
        // Search through all defined data in the program
        Listing listing = currentProgram.getListing();
        DataIterator dataIter = listing.getDefinedData(true);
        
        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            DataType dataType = data.getDataType();
            
            if (dataType.equals(table)) {
                locations.add(data.getAddress());
            }
        }
        
        return locations;
    }
    
    /**
     * Extracts function addresses from a table at a specific memory location
     */
    private List<Address> extractFunctionAddressesFromTable(StructureDataType table, 
            Address tableAddr, Memory memory, int pointerSize) throws MemoryAccessException {
        
        List<Address> addresses = new ArrayList<>();
        DataTypeComponent[] components = table.getDefinedComponents();
        
        for (DataTypeComponent component : components) {
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
        
        return addresses;
    }
    
    /**
     * Checks if a function signature has changed compared to stored definition
     */
    private boolean signatureChanged(Function currentFunc, FunctionDefinitionDataType storedDef) {
        FunctionSignature currentSig = currentFunc.getSignature();
        
        // Compare return types
        if (!typesEqual(currentSig.getReturnType(), storedDef.getReturnType())) {
            return true;
        }
        
        // Compare parameter counts
        ParameterDefinition[] currentParams = currentSig.getArguments();
        ParameterDefinition[] storedParams = storedDef.getArguments();
        
        if (currentParams.length != storedParams.length) {
            return true;
        }
        
        // Compare parameter types
        for (int i = 0; i < currentParams.length; i++) {
            if (!typesEqual(currentParams[i].getDataType(), storedParams[i].getDataType())) {
                return true;
            }
        }
        
        // Compare calling conventions
        String currentCC = currentSig.getCallingConventionName();
        String storedCC = storedDef.getCallingConventionName();
        
        if (!Objects.equals(currentCC, storedCC)) {
            return true;
        }
        
        // Compare varargs
        if (currentSig.hasVarArgs() != storedDef.hasVarArgs()) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Compares two data types for equality
     */
    private boolean typesEqual(DataType type1, DataType type2) {
        if (type1 == null && type2 == null) {
            return true;
        }
        if (type1 == null || type2 == null) {
            return false;
        }
        
        return type1.isEquivalent(type2);
    }
    
    /**
     * Creates an updated function definition based on current function signature
     */
    private FunctionDefinitionDataType createUpdatedFunctionDefinition(Function currentFunc, 
            FunctionDefinitionDataType storedDef, DataTypeManager dtm) 
            throws DuplicateNameException, InvalidInputException {
        
        FunctionSignature currentSig = currentFunc.getSignature();
        
        // Create new function definition with updated signature
        String defName = storedDef.getName();
        FunctionDefinitionDataType updatedDef = new FunctionDefinitionDataType(defName);
        
        updatedDef.setReturnType(currentSig.getReturnType());
        updatedDef.setArguments(currentSig.getArguments());
        updatedDef.setCallingConvention(currentSig.getCallingConventionName());
        updatedDef.setVarArgs(currentSig.hasVarArgs());
        
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
    private StructureDataType rebuildTableStructure(StructureDataType originalTable, 
            Map<String, FunctionDefinitionDataType> updatedDefs, DataTypeManager dtm, 
            int pointerSize) throws DuplicateNameException, InvalidInputException {
        
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
        
        if (resolvedTable instanceof StructureDataType) {
            return (StructureDataType) resolvedTable;
        }
        
        return newTable;
    }
    
    /**
     * Applies an updated table structure to a memory location
     */
    private void applyUpdatedTable(Address tableAddr, StructureDataType oldTable, 
            StructureDataType newTable) throws Exception {
        
        // Clear existing data
        clearListing(tableAddr, tableAddr.add(oldTable.getLength() - 1));
        
        // Apply new data type
        createData(tableAddr, newTable);
        
        println("Applied updated table structure at " + tableAddr);
    }
    
    /**
     * Result class for tracking update statistics
     */
    private static class UpdateResult {
        int updatesApplied = 0;
        int tablesRebuilt = 0;
    }
}

