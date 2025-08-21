/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//A script that flattens structure data types by moving nested structure members
//directly into the parent structure, creating a new flattened structure.
//@author mobilemutex
//@category DataTypes
//@keybinding 
//@menupath Tools.Data Types.Flatten Structure
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidNameException;

import java.util.*;

public class FlattenStructureScript extends GhidraScript {

    // Helper class to represent a flattened component
    private static class FlattenedComponent {
        String name;
        DataType dataType;
        int offset;
        int length;
        String comment;
        
        FlattenedComponent(String name, DataType dataType, int offset, int length, String comment) {
            this.name = name;
            this.dataType = dataType;
            this.offset = offset;
            this.length = length;
            this.comment = comment;
        }
    }
    
    // Context class to maintain state during flattening
    private static class FlattenerContext {
        List<FlattenedComponent> flattenedComponents;
        Set<String> usedNames;
        DataTypeManager dataTypeManager;
        Set<String> processedStructures; // To detect circular references
        
        FlattenerContext(DataTypeManager dtm) {
            this.flattenedComponents = new ArrayList<>();
            this.usedNames = new HashSet<>();
            this.dataTypeManager = dtm;
            this.processedStructures = new HashSet<>();
        }
    }

    @Override
    protected void run() throws Exception {
        // Get the data type manager service
        PluginTool tool = state.getTool();
        DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
        if (service == null) {
            println("Could not get DataTypeManagerService");
            return;
        }

        // Ask user to select a structure to flatten
        DataType selectedDataType = askChoice("Select Structure to Flatten", 
            "Choose a structure data type to flatten:", 
            getAllStructures(service), null);
            
        if (selectedDataType == null) {
            println("No structure selected. Exiting.");
            return;
        }
        
        if (!(selectedDataType instanceof Structure)) {
            println("Selected data type is not a structure: " + selectedDataType.getName());
            return;
        }
        
        Structure originalStructure = (Structure) selectedDataType;
        println("Flattening structure: " + originalStructure.getName());
        
        // Check if structure has nested structures
        if (!hasNestedStructures(originalStructure)) {
            println("Structure '" + originalStructure.getName() + "' has no nested structures to flatten.");
            return;
        }
        
        try {
            // Flatten the structure
            Structure flattenedStructure = flattenStructure(originalStructure);
            
            if (flattenedStructure != null) {
                println("Successfully created flattened structure: " + flattenedStructure.getName());
                println("Original structure size: " + originalStructure.getLength() + " bytes");
                println("Flattened structure size: " + flattenedStructure.getLength() + " bytes");
                println("Original components: " + originalStructure.getNumComponents());
                println("Flattened components: " + flattenedStructure.getNumComponents());
                
                // Show the flattened structure details
                printStructureDetails(flattenedStructure);
            } else {
                println("Failed to create flattened structure.");
            }
        } catch (Exception e) {
            println("Error flattening structure: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Get all available structures from all data type managers
     */
    private List<Structure> getAllStructures(DataTypeManagerService service) {
        List<Structure> structures = new ArrayList<>();
        DataTypeManager[] managers = service.getDataTypeManagers();
        
        for (DataTypeManager manager : managers) {
            Iterator<DataType> iterator = manager.getAllDataTypes();
            while (iterator.hasNext()) {
                DataType dt = iterator.next();
                if (dt instanceof Structure) {
                    structures.add((Structure) dt);
                }
            }
        }
        
        // Sort by name for easier selection
        structures.sort((s1, s2) -> s1.getName().compareToIgnoreCase(s2.getName()));
        return structures;
    }
    
    /**
     * Check if a structure contains nested structures
     */
    private boolean hasNestedStructures(Structure structure) {
        DataTypeComponent[] components = structure.getComponents();
        for (DataTypeComponent component : components) {
            DataType componentType = component.getDataType();
            if (componentType instanceof Structure) {
                return true;
            }
            // Also check arrays of structures
            if (componentType instanceof Array) {
                Array arrayType = (Array) componentType;
                if (arrayType.getDataType() instanceof Structure) {
                    return true;
                }
            }
        }
        return false;
    }
    
    /**
     * Main method to flatten a structure
     */
    private Structure flattenStructure(Structure originalStructure) throws Exception {
        DataTypeManager dtm = originalStructure.getDataTypeManager();
        FlattenerContext context = new FlattenerContext(dtm);
        
        // Collect all flattened components
        collectFlattenedComponents(originalStructure, "", 0, context);
        
        if (context.flattenedComponents.isEmpty()) {
            println("No components to flatten.");
            return null;
        }
        
        // Create the flattened structure name
        String flattenedName = generateFlattenedName(originalStructure.getName(), dtm);
        
        // Sort components by offset to maintain proper structure layout
        context.flattenedComponents.sort((a, b) -> Integer.compare(a.offset, b.offset));
        
        // Create new structure with the original structure's size
        Structure flattenedStructure = new StructureDataType(flattenedName, originalStructure.getLength(), dtm);
        
        // Add all flattened components at their correct offsets
        for (FlattenedComponent comp : context.flattenedComponents) {
            try {
                // Use insertAtOffset to maintain proper memory layout
                flattenedStructure.insertAtOffset(comp.offset, comp.dataType, comp.length, comp.name, comp.comment);
            } catch (Exception e) {
                println("Warning: Could not add component '" + comp.name + "' at offset " + comp.offset + ": " + e.getMessage());
                // Fallback to regular add if insertAtOffset fails
                try {
                    flattenedStructure.add(comp.dataType, comp.length, comp.name, comp.comment);
                } catch (Exception e2) {
                    println("Warning: Could not add component '" + comp.name + "' with fallback method: " + e2.getMessage());
                }
            }
        }
        
        // Add the flattened structure to the data type manager
        try {
            DataType addedType = dtm.addDataType(flattenedStructure, DataTypeConflictHandler.REPLACE_HANDLER);
            return (Structure) addedType;
        } catch (Exception e) {
            println("Error adding flattened structure to data type manager: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Recursively collect all components that should be in the flattened structure
     */
    private void collectFlattenedComponents(Structure structure, String prefix, int baseOffset, 
                                          FlattenerContext context) {
        
        // Check for circular references
        String structureId = structure.getPathName();
        if (context.processedStructures.contains(structureId)) {
            println("Warning: Circular reference detected for structure: " + structure.getName());
            return;
        }
        context.processedStructures.add(structureId);
        
        DataTypeComponent[] components = structure.getComponents();
        
        for (DataTypeComponent component : components) {
            DataType componentType = component.getDataType();
            String componentName = component.getFieldName();
            if (componentName == null || componentName.isEmpty()) {
                componentName = "field_" + component.getOrdinal();
            }
            
            String fullName = prefix.isEmpty() ? componentName : prefix + "_" + componentName;
            fullName = generateUniqueName(fullName, context.usedNames);
            
            int componentOffset = baseOffset + component.getOffset();
            
            if (componentType instanceof Structure) {
                // Recursively flatten nested structure
                Structure nestedStructure = (Structure) componentType;
                collectFlattenedComponents(nestedStructure, fullName, componentOffset, context);
            } else if (componentType instanceof Array) {
                // Handle arrays
                Array arrayType = (Array) componentType;
                DataType elementType = arrayType.getDataType();
                
                if (elementType instanceof Structure) {
                    // Array of structures - flatten each element
                    Structure elementStructure = (Structure) elementType;
                    int elementSize = elementStructure.getLength();
                    int numElements = arrayType.getNumElements();
                    
                    for (int i = 0; i < numElements; i++) {
                        String arrayElementPrefix = fullName + "_" + i;
                        int elementOffset = componentOffset + (i * elementSize);
                        collectFlattenedComponents(elementStructure, arrayElementPrefix, 
                                                 elementOffset, context);
                    }
                } else {
                    // Array of primitives - add as single component
                    FlattenedComponent flatComp = new FlattenedComponent(
                        fullName, componentType, componentOffset, 
                        component.getLength(), component.getComment());
                    context.flattenedComponents.add(flatComp);
                }
            } else {
                // Primitive type - add directly
                FlattenedComponent flatComp = new FlattenedComponent(
                    fullName, componentType, componentOffset, 
                    component.getLength(), component.getComment());
                context.flattenedComponents.add(flatComp);
            }
        }
        
        // Remove from processed set when done (for proper handling of multiple references)
        context.processedStructures.remove(structureId);
    }
    
    /**
     * Generate a unique name to avoid conflicts
     */
    private String generateUniqueName(String baseName, Set<String> usedNames) {
        String uniqueName = baseName;
        int counter = 1;
        
        while (usedNames.contains(uniqueName)) {
            uniqueName = baseName + "_" + counter;
            counter++;
        }
        
        usedNames.add(uniqueName);
        return uniqueName;
    }
    
    /**
     * Generate a name for the flattened structure
     */
    private String generateFlattenedName(String originalName, DataTypeManager dtm) {
        String baseName = originalName + "_flattened";
        String uniqueName = baseName;
        int counter = 1;
        
        while (dtm.getDataType(uniqueName) != null) {
            uniqueName = baseName + "_" + counter;
            counter++;
        }
        
        return uniqueName;
    }
    
    /**
     * Print details of the flattened structure
     */
    private void printStructureDetails(Structure structure) {
        println("\n=== Flattened Structure Details ===");
        println("Name: " + structure.getName());
        println("Size: " + structure.getLength() + " bytes");
        println("Alignment: " + structure.getAlignment());
        println("Components:");
        
        DataTypeComponent[] components = structure.getComponents();
        for (int i = 0; i < components.length; i++) {
            DataTypeComponent comp = components[i];
            println(String.format("  [%d] %s %s (offset: %d, size: %d)", 
                i, comp.getDataType().getName(), comp.getFieldName(), 
                comp.getOffset(), comp.getLength()));
        }
        println("=== End Structure Details ===\n");
    }
}

