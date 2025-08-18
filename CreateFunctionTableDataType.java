//Creates data types for function tables by analyzing selected function pointers,
//creating function definition data types, and applying a structure data type to the table.
//@author mobilemutex
//@category Data Types
//@keybinding 
//@menupath Tools.Data Types.Create Function Table Data Type
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

public class CreateFunctionTableDataType extends GhidraScript {
    
    private static final String DEFAULT_TABLE_NAME = "FunctionTable";
    private static final String DEFAULT_FUNC_PREFIX = "func_";
    
    @Override
    public void run() throws Exception {
        // Validate that we have a selection
        if (currentSelection == null || currentSelection.isEmpty()) {
            popup("Please select a memory region containing function pointers before running this script.");
            return;
        }
        
        // Get basic program information
        Memory memory = currentProgram.getMemory();
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        int pointerSize = currentProgram.getDefaultPointerSize();
        
        println("Starting Function Table Data Type Creation...");
        println("Pointer size: " + pointerSize + " bytes");
        println("Selected range: " + currentSelection.toString());
        
        try {
            // Step 1: Extract function addresses from selection
            List<Address> functionAddresses = extractFunctionAddresses(memory, pointerSize);
            if (functionAddresses.isEmpty()) {
                popup("No valid function pointers found in the selected region.");
                return;
            }
            
            println("Found " + functionAddresses.size() + " function addresses");
            
            // Step 2: Analyze functions and create function definition data types
            Map<String, FunctionDefinitionDataType> functionDefs = createFunctionDefinitions(
                funcMgr, dtm, functionAddresses);
            
            if (functionDefs.isEmpty()) {
                popup("No valid functions found at the specified addresses.");
                return;
            }
            
            println("Created " + functionDefs.size() + " function definition data types");
            
            // Step 3: Create the function table structure
            StructureDataType tableStruct = createFunctionTableStructure(
                dtm, functionDefs, functionAddresses, pointerSize);
            
            // Step 4: Apply the data type to the selection
            applyDataTypeToSelection(dtm, tableStruct);
            
            println("Successfully created and applied function table data type: " + tableStruct.getName());
            popup("Function table data type created successfully!\\n" +
                  "Table: " + tableStruct.getName() + "\\n" +
                  "Functions: " + functionDefs.size() + "\\n" +
                  "Size: " + tableStruct.getLength() + " bytes");
            
        } catch (Exception e) {
            printerr("Error creating function table data type: " + e.getMessage());
            e.printStackTrace();
            popup("Error: " + e.getMessage());
        }
    }
    
    /**
     * Extracts function addresses from the selected memory region
     */
    private List<Address> extractFunctionAddresses(Memory memory, int pointerSize) 
            throws MemoryAccessException {
        List<Address> addresses = new ArrayList<>();
        
        for (AddressRange range : currentSelection) {
            Address addr = range.getMinAddress();
            Address endAddr = range.getMaxAddress();
            
            // Ensure we're aligned to pointer boundaries
            long offset = addr.getOffset() % pointerSize;
            if (offset != 0) {
                addr = addr.add(pointerSize - offset);
                println("Adjusting start address to pointer boundary: " + addr);
            }
            
            while (addr.compareTo(endAddr) <= 0 && 
                   addr.add(pointerSize - 1).compareTo(endAddr) <= 0) {
                try {
                    // Read pointer value
                    long pointerValue;
                    if (pointerSize == 8) {
                        pointerValue = memory.getLong(addr);
                    } else if (pointerSize == 4) {
                        pointerValue = memory.getInt(addr) & 0xFFFFFFFFL;
                    } else if (pointerSize == 2) {
                        pointerValue = memory.getShort(addr) & 0xFFFFL;
                    } else {
                        throw new IllegalArgumentException("Unsupported pointer size: " + pointerSize);
                    }
                    
                    // Convert to address
                    Address targetAddr = currentProgram.getAddressFactory()
                        .getDefaultAddressSpace().getAddress(pointerValue);
                    
                    // Validate the address is in memory
                    if (memory.contains(targetAddr)) {
                        addresses.add(targetAddr);
                        println("Found function pointer at " + addr + " -> " + targetAddr);
                    } else {
                        println("Invalid address at " + addr + " -> " + targetAddr + " (not in memory)");
                    }
                    
                } catch (MemoryAccessException e) {
                    println("Memory access error at " + addr + ": " + e.getMessage());
                }
                
                addr = addr.add(pointerSize);
            }
        }
        
        return addresses;
    }
    
    /**
     * Creates function definition data types for the discovered functions
     */
    private Map<String, FunctionDefinitionDataType> createFunctionDefinitions(
            FunctionManager funcMgr, DataTypeManager dtm, List<Address> functionAddresses) 
            throws DuplicateNameException, InvalidInputException {
        
        Map<String, FunctionDefinitionDataType> functionDefs = new LinkedHashMap<>();
        Set<String> usedNames = new HashSet<>();
        
        for (int i = 0; i < functionAddresses.size(); i++) {
            Address addr = functionAddresses.get(i);
            Function func = funcMgr.getFunctionAt(addr);
            
            String funcName;
            FunctionSignature signature;
            
            if (func != null) {
                // Use existing function information
                funcName = func.getName();
                signature = func.getSignature();
                println("Found function: " + funcName + " at " + addr);
            } else {
                // Create a generic function definition
                funcName = "unknown_func_" + addr.toString().replace(":", "_");
                signature = createGenericFunctionSignature(dtm, funcName);
                println("Creating generic function definition for address: " + addr);
            }
            
            // Ensure unique name for the function definition data type
            String defName = funcName + "_def";
            if (usedNames.contains(defName)) {
                int counter = 1;
                String baseName = defName;
                do {
                    defName = baseName + "_" + counter++;
                } while (usedNames.contains(defName));
            }
            usedNames.add(defName);
            
            // Create function definition data type
            FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType(defName);
            funcDef.setReturnType(signature.getReturnType());
            funcDef.setArguments(signature.getArguments());
            funcDef.setCallingConvention(signature.getCallingConventionName());
            funcDef.setVarArgs(signature.hasVarArgs());
            
            // Add to data type manager
            DataType resolvedDef = dtm.addDataType(funcDef, DataTypeConflictHandler.REPLACE_HANDLER);
            if (resolvedDef instanceof FunctionDefinitionDataType) {
                functionDefs.put("func_" + i, (FunctionDefinitionDataType) resolvedDef);
            }
        }
        
        return functionDefs;
    }
    
    /**
     * Creates a generic function signature for unknown functions
     */
    private FunctionSignature createGenericFunctionSignature(DataTypeManager dtm, String name) {
        DataType voidType = dtm.getDataType("/void");
        if (voidType == null) {
            voidType = VoidDataType.dataType;
        }
        
        return new FunctionSignatureImpl(name, voidType, new ParameterDefinition[0], false);
    }
    
    /**
     * Creates the function table structure data type
     */
    private StructureDataType createFunctionTableStructure(
            DataTypeManager dtm, Map<String, FunctionDefinitionDataType> functionDefs,
            List<Address> functionAddresses, int pointerSize) 
            throws DuplicateNameException, InvalidInputException {
        
        // Get a unique name for the table
        String tableName = getUniqueDataTypeName(dtm, DEFAULT_TABLE_NAME);
        
        StructureDataType tableStruct = new StructureDataType(tableName, 0);
        
        int index = 0;
        for (Map.Entry<String, FunctionDefinitionDataType> entry : functionDefs.entrySet()) {
            String fieldName = entry.getKey();
            FunctionDefinitionDataType funcDef = entry.getValue();
            
            // Create pointer to function definition
            PointerDataType funcPtr = new PointerDataType(funcDef, pointerSize);
            
            // Add field to structure
            tableStruct.add(funcPtr, fieldName, "Function pointer " + index + 
                           " -> " + functionAddresses.get(index));
            index++;
        }
        
        // Add the structure to the data type manager
        DataType resolvedStruct = dtm.addDataType(tableStruct, DataTypeConflictHandler.REPLACE_HANDLER);
        
        if (!(resolvedStruct instanceof StructureDataType)) {
            throw new RuntimeException("Failed to create structure data type");
        }
        
        return (StructureDataType) resolvedStruct;
    }
    
    /**
     * Applies the function table data type to the selected memory region
     */
    private void applyDataTypeToSelection(DataTypeManager dtm, StructureDataType tableStruct) 
            throws Exception {
        
        Address startAddr = currentSelection.getMinAddress();
        
        // Clear any existing data at the location
        clearListing(startAddr, startAddr.add(tableStruct.getLength() - 1));
        
        // Apply the new data type
        createData(startAddr, tableStruct);
        
        // Set a label if one doesn't exist
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        Symbol[] symbols = symbolTable.getSymbols(startAddr);
        if (symbols.length == 0) {
            try {
                symbolTable.createLabel(startAddr, tableStruct.getName(), 
                                      SourceType.USER_DEFINED);
            } catch (InvalidInputException e) {
                println("Could not create label: " + e.getMessage());
            }
        }
        
        println("Applied data type " + tableStruct.getName() + " at " + startAddr);
    }
    
    /**
     * Gets a unique data type name by appending a number if necessary
     */
    private String getUniqueDataTypeName(DataTypeManager dtm, String baseName) {
        String name = baseName;
        int counter = 1;
        
        while (dtm.getDataType("/" + name) != null) {
            name = baseName + "_" + counter++;
        }
        
        return name;
    }
}

