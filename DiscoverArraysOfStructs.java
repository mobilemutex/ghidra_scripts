//Attempts to automatically discovers and analyze arrays of structs within binary executables
//@category Analysis.Structures
//@author mobilemutex
//@menupath

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;
import java.util.*;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.FileOutputStream;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;

public class DiscoverArraysOfStructs extends GhidraScript {

    // ========================================
    // GLOBAL CONFIGURATION VARIABLES
    // ========================================

    // Memory Scope Options
    private boolean UNDEFINED_MEMORY_ONLY = false;

    // Alignment Constraints for array starting addresses
    private int REQUIRED_ALIGNMENT = 4; // Valid values: 2, 4, or 8 bytes

    // Operation Mode
    private boolean AUTO_CREATE_STRUCTURES = false; // When false, only print to console

    // Analysis Region
    private boolean ANALYZE_ENTIRE_BINARY = false;
    private long START_ADDRESS = 0x00479bacL; // Used when ANALYZE_ENTIRE_BINARY is false
    private long END_ADDRESS = 0x00479cecL;   // Used when ANALYZE_ENTIRE_BINARY is false

    // Internal Configuration
    private int MIN_REPETITIONS = 3; // Minimum repetitions to consider a valid pattern
    private int MIN_STRUCT_SIZE = 8;
    private int MAX_STRUCT_SIZE = 128;
    private int POINTER_SIZE = 0; // Will be set based on program architecture
    private boolean VERBOSE_OUTPUT = true;
    private boolean DEBUG_OUTPUT = true; // Detailed debug information

    // Data structures for discovered patterns
    private List<StructPattern> discoveredPatterns = new ArrayList<>();
    private Set<Address> processedAddresses = new HashSet<>();
    
    // File output handling
    private PrintWriter fileWriter;
    private String outputFileName;

    /**
     * Represents a discovered struct array pattern
     */
    private class StructPattern {
        Address startAddress;
        int structSize;
        int arrayCount;
        int confidence;
        List<FieldInfo> fields;
        String patternType;

        public StructPattern(Address start, int size, int count) {
            this.startAddress = start;
            this.structSize = size;
            this.arrayCount = count;
            this.fields = new ArrayList<>();
            this.confidence = 0;
        }
    }

    /**
     * Represents a field within a discovered struct
     */
    private class FieldInfo {
        int offset;
        DataType dataType;
        int size;
        String description;

        public FieldInfo(int offset, DataType type, int size, String desc) {
            this.offset = offset;
            this.dataType = type;
            this.size = size;
            this.description = desc;
        }
    }

    @Override
    public void run() throws Exception {
        // Initialize file output
        initializeFileOutput();
        
        validateConfiguration();
        initializePointerSize();

        println("========================================");
        println("Array of Structs Discovery Script");
        println("========================================");
        println("Configuration:");
        println("  - Auto-create structures: " + AUTO_CREATE_STRUCTURES);
        println("  - Required alignment: " + REQUIRED_ALIGNMENT);
        println("  - Minimum repetitions: " + MIN_REPETITIONS);
        println("  - Pointer size: " + POINTER_SIZE + " bytes");
        println("  - Output file: " + outputFileName);
        println("========================================\n");

        // Determine analysis boundaries
        AddressSetView analyzableAddresses = getAnalyzableAddresses();

        // Run pattern detection strategies
        println("Starting pattern detection...");
        detectPatterns(analyzableAddresses);

        // Group patterns by starting address and select the best one for each address
        Map<Address, List<StructPattern>> patternsByAddress = groupPatternsByAddress(discoveredPatterns);
        List<StructPattern> bestPatterns = selectBestPatterns(patternsByAddress);

        // Sort the best patterns by address (lowest address first)
        bestPatterns.sort(Comparator.comparing(p -> p.startAddress));

        // Output results
        println("\n========================================");
        println("Pattern Detection Complete");
        println("Found " + discoveredPatterns.size() + " potential struct arrays");
        println("Selected " + bestPatterns.size() + " best patterns (one per address)");
        println("========================================\n");

        // Process patterns in address order, checking for overlaps
        Set<Address> processedAddresses = new HashSet<>();
        for (StructPattern pattern : bestPatterns) {
            // Check if this pattern overlaps with any already processed address
            boolean hasOverlap = false;
            for (int i = 0; i < pattern.arrayCount; i++) {
                Address elementStart = pattern.startAddress.add(i * pattern.structSize);
                for (int offset = 0; offset < pattern.structSize; offset++) {
                    try {
                        Address checkAddr = elementStart.add(offset);
                        if (processedAddresses.contains(checkAddr)) {
                            hasOverlap = true;
                            break;
                        }
                    } catch (Exception e) {
                        // Skip if address calculation fails
                    }
                }
                if (hasOverlap) break;
            }
            
            if (hasOverlap) {
                if (VERBOSE_OUTPUT) {
                    println("Skipping pattern at " + pattern.startAddress +
                           " - overlaps with already processed memory");
                }
                continue;
            }
            
            printPattern(pattern);

            if (AUTO_CREATE_STRUCTURES) {
                createStructureAndArray(pattern);
            }
            
            // Mark all addresses in this pattern as processed
            for (int i = 0; i < pattern.arrayCount; i++) {
                Address elementStart = pattern.startAddress.add(i * pattern.structSize);
                for (int offset = 0; offset < pattern.structSize; offset++) {
                    try {
                        processedAddresses.add(elementStart.add(offset));
                    } catch (Exception e) {
                        // Skip if address calculation fails
                    }
                }
            }
        }

        println("\nAnalysis complete!");
        
        // Close file output
        closeFileOutput();
    }

    /**
     * Validates configuration parameters
     */
    private void validateConfiguration() throws Exception {
        if (REQUIRED_ALIGNMENT != 2 && REQUIRED_ALIGNMENT != 4 && REQUIRED_ALIGNMENT != 8) {
            throw new Exception("Invalid REQUIRED_ALIGNMENT. Must be 2, 4, or 8.");
        }
        if (!ANALYZE_ENTIRE_BINARY && START_ADDRESS >= END_ADDRESS) {
            throw new Exception("Invalid address range: START_ADDRESS must be less than END_ADDRESS");
        }
    }
    
    /**
     * Initializes file output with timestamped filename
     */
    private void initializeFileOutput() throws IOException {
        // Create timestamp for filename
        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss");
        String timestamp = now.format(formatter);
        
        // Create filename with full path to script directory
        String scriptPath = getSourceFile().getParentFile().getAbsolutePath();
        outputFileName = scriptPath + "/discoverArraysOfStructs_" + timestamp + ".txt";
        
        // Initialize file writer
        fileWriter = new PrintWriter(new FileOutputStream(outputFileName, true), true);
        
        // Write header to file
        fileWriter.println("========================================");
        fileWriter.println("Array of Structs Discovery Script Output");
        fileWriter.println("Generated: " + now.toString());
        fileWriter.println("Output file: " + outputFileName);
        fileWriter.println("========================================");
        fileWriter.println();
    }
    
    /**
     * Closes file output
     */
    private void closeFileOutput() {
        if (fileWriter != null) {
            fileWriter.println("========================================");
            fileWriter.println("End of Analysis Output");
            fileWriter.println("========================================");
            fileWriter.close();
            fileWriter = null;
        }
    }
    
    /**
     * Override println to write to both console and file
     */
    @Override
    public void println(String message) {
        // Write to console (original behavior)
        super.println(message);
        
        // Write to file if available
        if (fileWriter != null) {
            fileWriter.println(message);
        }
    }

    /**
     * Initializes pointer size based on program architecture
     */
    private void initializePointerSize() {
        POINTER_SIZE = currentProgram.getDefaultPointerSize();
    }

    /**
     * Determines which addresses should be analyzed
     */
    private AddressSetView getAnalyzableAddresses() {
        if (ANALYZE_ENTIRE_BINARY) {
            return currentProgram.getMemory();
        } else {
            Address start = currentProgram.getAddressFactory().getDefaultAddressSpace()
                .getAddress(START_ADDRESS);
            Address end = currentProgram.getAddressFactory().getDefaultAddressSpace()
                .getAddress(END_ADDRESS);
            return new AddressSet(start, end);
        }
    }

    /**
     * Main pattern detection orchestrator
     */
    private void detectPatterns(AddressSetView addresses) throws Exception {
        Memory memory = currentProgram.getMemory();

        // Iterate through memory blocks
        for (MemoryBlock block : memory.getBlocks()) {
            if (!shouldAnalyzeBlock(block)) {
                continue;
            }
            
            // Check if this block intersects with our target addresses
            AddressSet blockAddresses = new AddressSet(block.getStart(), block.getEnd());
            AddressSet intersection = addresses.intersect(blockAddresses);
            
            if (intersection.isEmpty()) {
                continue; // Skip blocks that don't intersect with our target addresses
            }

            println("Analyzing block: " + block.getName() +
                   " [" + block.getStart() + " - " + block.getEnd() + "] (restricted to provided addresses)");

            // Strategy 1: Evenly spaced pointer patterns
            detectEvenlySpacedPointers(block, addresses);

            // Strategy 2: Repeating composite data type sequences
            //detectRepeatingCompositeSequences(block, addresses);

            // Strategy 3: Field alignment and padding patterns
            // Not robust enough yet, so disabled for now
            //detectAlignmentPatterns(block, addresses);

            // Strategy 4: Cross-reference analysis
            detectCrossReferencePatterns(block, addresses);
        }
    }

    /**
     * Determines if a memory block should be analyzed
     */
    private boolean shouldAnalyzeBlock(MemoryBlock block) {
        // Skip external blocks
        if (block.getName().equals(MemoryBlock.EXTERNAL_BLOCK_NAME)) {
            return false;
        }

        // Check if block is initialized based on configuration
        if (UNDEFINED_MEMORY_ONLY && block.isInitialized()) {
            return false;
        }

        return true;
    }

    /**
     * Strategy 1: Detect evenly spaced pointer patterns
     * Looks for pointers at regular intervals with data in between
     */
    private void detectEvenlySpacedPointers(MemoryBlock block, AddressSetView addresses) throws Exception {
        Address current = block.getStart();
        Address blockEnd = block.getEnd();

        while (current != null && current.compareTo(blockEnd) < 0) {
            // Skip addresses not in our target set
            if (!addresses.contains(current)) {
                current = current.add(REQUIRED_ALIGNMENT);
                continue;
            }
            if (processedAddresses.contains(current)) {
                current = current.add(REQUIRED_ALIGNMENT);
                continue;
            }

            // Check if current address is properly aligned
            if (current.getOffset() % REQUIRED_ALIGNMENT != 0) {
                current = current.add(1);
                continue;
            }

            // Try to detect a pattern of evenly spaced pointers
            List<Integer> strides = new ArrayList<>();
            if (DEBUG_OUTPUT) {
                println("DEBUG: Checking evenly spaced pointers at address " + current);
            }
            
            for (int stride = MIN_STRUCT_SIZE; stride <= MAX_STRUCT_SIZE; stride += REQUIRED_ALIGNMENT) {
                int repetitions = countPointerRepetitions(current, stride, blockEnd, addresses);
                // Require more repetitions for smaller struct sizes to avoid false positives
                int minRepsForSize = (stride <= 8) ? MIN_REPETITIONS + 2 : MIN_REPETITIONS;
                
                if (DEBUG_OUTPUT) {
                    println("DEBUG:   Stride " + stride + " bytes: " + repetitions + " repetitions (min required: " + minRepsForSize + ")");
                }
                
                if (repetitions >= minRepsForSize) {
                    strides.add(stride);
                    if (DEBUG_OUTPUT) {
                        println("DEBUG:   ✓ ACCEPTED stride " + stride + " with " + repetitions + " repetitions");
                    }
                } else {
                    if (DEBUG_OUTPUT) {
                        //println("DEBUG:   ✗ REJECTED stride " + stride + " - insufficient repetitions");
                    }
                }
            }
            
            if (DEBUG_OUTPUT) {
                println("DEBUG: Found " + strides.size() + " valid strides at address " + current);
            }

            // Process each detected stride but don't mark addresses as processed yet
            // We'll let the pattern selection handle that
            for (int stride : strides) {
                // Skip if this stride is a multiple of a smaller valid stride
                boolean isMultipleOfSmaller = false;
                for (int smallerStride : strides) {
                    if (stride != smallerStride && stride % smallerStride == 0) {
                        isMultipleOfSmaller = true;
                        if (DEBUG_OUTPUT) {
                            println("DEBUG:   ✗ REJECTED stride " + stride + " - is a multiple of smaller stride " + smallerStride);
                        }
                        break;
                    }
                }
                
                if (isMultipleOfSmaller) {
                    continue;
                }
                
                int count = countPointerRepetitions(current, stride, blockEnd, addresses);
                StructPattern pattern = new StructPattern(current, stride, count);
                pattern.patternType = "Evenly Spaced Pointers";

                if (DEBUG_OUTPUT) {
                    println("DEBUG: Creating pattern - Type: " + pattern.patternType +
                           ", Address: " + current + ", Stride: " + stride + ", Count: " + count);
                }

                // Analyze the structure of each element first
                analyzeStructureFields(pattern);
                
                // Calculate confidence with enhanced scoring
                pattern.confidence = calculateConfidence(count, stride, pattern.patternType,
                                                         pattern.fields, current, count);

                if (DEBUG_OUTPUT) {
                    println("DEBUG: Pattern confidence calculated: " + pattern.confidence + "%");
                    println("DEBUG: Fields detected: " + pattern.fields.size());
                    for (FieldInfo field : pattern.fields) {
                        println("DEBUG:   Field at offset 0x" + String.format("%02X", field.offset) +
                               ": " + field.description + " (" + field.size + " bytes)");
                    }
                }

                discoveredPatterns.add(pattern);
            }

            // Skip to the next unprocessed address
            current = current.add(REQUIRED_ALIGNMENT);
            while (current != null && current.compareTo(blockEnd) < 0 && processedAddresses.contains(current)) {
                current = current.add(1);
            }
        }
    }

    /**
     * Counts how many times a pointer pattern repeats at the given stride
     */
    private int countPointerRepetitions(Address start, int stride, Address endAddr, AddressSetView addresses) {
        int count = 0;
        Address current = start;

        try {
            while (current != null && current.compareTo(endAddr) <= 0) {
                // Skip addresses not in our target set
                if (!addresses.contains(current)) {
                    current = current.add(stride);
                    continue;
                }
                
                if (!isValidPointer(current)) {
                    break;
                }
                count++;
                current = current.add(stride);
            }
        } catch (Exception e) {
            // Address calculation error
        }

        return count;
    }

    /**
     * Checks if the address contains a valid pointer
     */
    private boolean isValidPointer(Address addr) {
        try {
            Memory memory = currentProgram.getMemory();
            byte[] bytes = new byte[POINTER_SIZE];
            memory.getBytes(addr, bytes);

            // Reconstruct pointer value
            long pointerValue = 0;
            boolean isLittleEndian = currentProgram.getLanguage().isBigEndian() == false;

            for (int i = 0; i < POINTER_SIZE; i++) {
                int byteIndex = isLittleEndian ? i : (POINTER_SIZE - 1 - i);
                pointerValue |= ((long)(bytes[byteIndex] & 0xFF)) << (i * 8);
            }

            // Check if pointer value is reasonable
            if (pointerValue == 0) {
                return false; // NULL pointers should not be considered valid for struct analysis
            }

            // Try to create an address from the pointer value
            Address targetAddr = currentProgram.getAddressFactory()
                .getDefaultAddressSpace().getAddress(pointerValue);

            // Check if the target address is valid in program memory
            return currentProgram.getMemory().contains(targetAddr);

        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Strategy 2: Detect repeating composite data type sequences
     */
    private void detectRepeatingCompositeSequences(MemoryBlock block, AddressSetView addresses) throws Exception {
        Address current = block.getStart();
        Address blockEnd = block.getEnd();

        while (current != null && current.compareTo(blockEnd) < 0) {
            // Skip addresses not in our target set
            if (!addresses.contains(current)) {
                current = current.add(REQUIRED_ALIGNMENT);
                continue;
            }
            if (processedAddresses.contains(current)) {
                current = current.add(REQUIRED_ALIGNMENT);
                continue;
            }

            if (DEBUG_OUTPUT) {
                println("DEBUG: Checking repeating composite sequences at address " + current);
            }
            
            // Try different struct sizes
            List<Integer> validSizes = new ArrayList<>();
            for (int structSize = MIN_STRUCT_SIZE; structSize <= MAX_STRUCT_SIZE;
                 structSize += REQUIRED_ALIGNMENT) {

                int repetitions = countSequenceRepetitions(current, structSize, blockEnd, addresses);
                
                // Require more repetitions for smaller struct sizes to avoid false positives
                int minRepsForSize = (structSize <= 8) ? MIN_REPETITIONS + 2 : MIN_REPETITIONS;

                if (DEBUG_OUTPUT) {
                    println("DEBUG:   Size " + structSize + " bytes: " + repetitions + " repetitions (min required: " + minRepsForSize + ")");
                }

                if (repetitions >= minRepsForSize) {
                    validSizes.add(structSize);
                    if (DEBUG_OUTPUT) {
                        println("DEBUG:   ✓ ACCEPTED size " + structSize + " with " + repetitions + " repetitions");
                    }
                } else {
                    if (DEBUG_OUTPUT) {
                        //println("DEBUG:   ✗ REJECTED size " + structSize + " - insufficient repetitions");
                    }
                }
            }
            
            // Process valid sizes, but skip multiples of smaller valid sizes
            for (int structSize : validSizes) {
                // Skip if this size is a multiple of a smaller valid size
                boolean isMultipleOfSmaller = false;
                for (int smallerSize : validSizes) {
                    if (structSize != smallerSize && structSize % smallerSize == 0) {
                        isMultipleOfSmaller = true;
                        if (DEBUG_OUTPUT) {
                            println("DEBUG:   ✗ REJECTED size " + structSize + " - is a multiple of smaller size " + smallerSize);
                        }
                        break;
                    }
                }
                
                if (isMultipleOfSmaller) {
                    continue;
                }
                
                int repetitions = countSequenceRepetitions(current, structSize, blockEnd, addresses);
                StructPattern pattern = new StructPattern(current, structSize, repetitions);
                pattern.patternType = "Repeating Composite Sequence";

                if (DEBUG_OUTPUT) {
                    println("DEBUG: Creating pattern - Type: " + pattern.patternType +
                           ", Address: " + current + ", Size: " + structSize + ", Count: " + repetitions);
                }

                // Analyze the structure first
                analyzeStructureFields(pattern);
                
                // Calculate confidence with enhanced scoring
                pattern.confidence = calculateConfidence(repetitions, structSize, pattern.patternType,
                                                         pattern.fields, current, repetitions);

                if (DEBUG_OUTPUT) {
                    println("DEBUG: Pattern confidence calculated: " + pattern.confidence + "%");
                    println("DEBUG: Fields detected: " + pattern.fields.size());
                    for (FieldInfo field : pattern.fields) {
                        println("DEBUG:   Field at offset 0x" + String.format("%02X", field.offset) +
                               ": " + field.description + " (" + field.size + " bytes)");
                    }
                }

                discoveredPatterns.add(pattern);

                break; // Move to next address
            }

            // Skip to the next unprocessed address
            current = current.add(REQUIRED_ALIGNMENT);
            while (current != null && current.compareTo(blockEnd) < 0 && processedAddresses.contains(current)) {
                current = current.add(1);
            }
        }
    }

    /**
     * Counts repetitions of a sequence pattern
     */
    private int countSequenceRepetitions(Address start, int size, Address endAddr, AddressSetView addresses) {
        try {
            Memory memory = currentProgram.getMemory();
            byte[] firstPattern = new byte[size];
            memory.getBytes(start, firstPattern);

            int count = 1; // First occurrence
            Address current = start.add(size);

            while (current != null && current.add(size - 1).compareTo(endAddr) <= 0) {
                // Skip addresses not in our target set
                if (!addresses.contains(current)) {
                    current = current.add(size);
                    continue;
                }
                
                // Check if pattern continues (with some tolerance)
                if (hasStructureSimilarity(current, firstPattern, size)) {
                    count++;
                    current = current.add(size);
                } else {
                    break;
                }
            }

            return count;

        } catch (Exception e) {
            return 0;
        }
    }

    /**
     * Checks if memory at address has structural similarity to a pattern
     */
    private boolean hasStructureSimilarity(Address addr, byte[] pattern, int size) {
        try {
            Memory memory = currentProgram.getMemory();
            byte[] currentBytes = new byte[size];
            memory.getBytes(addr, currentBytes);

            // Check for structural patterns (pointers in same positions, etc.)
            int similarPositions = 0;
            int nullBytePositions = 0;

            for (int i = 0; i < size; i += REQUIRED_ALIGNMENT) {
                boolean firstIsPointer = isPointerAtOffset(addr.subtract(size), i);
                boolean currentIsPointer = isPointerAtOffset(addr, i);

                if (firstIsPointer == currentIsPointer) {
                    similarPositions++;
                }
                
                // Check if current position has null bytes (all zeros)
                boolean currentIsNull = true;
                for (int j = 0; j < REQUIRED_ALIGNMENT; j++) {
                    if (currentBytes[i + j] != 0) {
                        currentIsNull = false;
                        break;
                    }
                }
                
                // Check if pattern position has null bytes (all zeros)
                boolean patternIsNull = true;
                for (int j = 0; j < REQUIRED_ALIGNMENT; j++) {
                    if (pattern[i + j] != 0) {
                        patternIsNull = false;
                        break;
                    }
                }
                
                // If both are null, that's a match for null data
                if (currentIsNull && patternIsNull) {
                    similarPositions++;
                }
                // If pattern has null but current doesn't, that's a mismatch
                else if (patternIsNull && !currentIsNull) {
                    similarPositions--; // Penalize this mismatch
                }
                
                if (currentIsNull) {
                    nullBytePositions++;
                }
            }

            // If more than 50% of alignment positions have similar structure
            int totalPositions = size / REQUIRED_ALIGNMENT;
            boolean hasSimilarity = (similarPositions * 2) > totalPositions;
            
            // Additional check: if most of the struct is null bytes, be more strict
            if (nullBytePositions > totalPositions / 2) {
                // If mostly null bytes, require exact match
                return Arrays.equals(currentBytes, pattern);
            }
            
            return hasSimilarity;

        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Checks if there's a pointer at a specific offset from base address
     */
    private boolean isPointerAtOffset(Address base, int offset) {
        try {
            Address addr = base.add(offset);
            return isValidPointer(addr);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Strategy 3: Detect field alignment and padding patterns
     */
    private void detectAlignmentPatterns(MemoryBlock block, AddressSetView addresses) throws Exception {
        // This strategy looks for consistent padding patterns
        // Implementation focuses on detecting null-byte padding at regular intervals

        Address current = block.getStart();
        Address blockEnd = block.getEnd();

        while (current != null && current.compareTo(blockEnd) < 0) {
            // Skip addresses not in our target set
            if (!addresses.contains(current)) {
                current = current.add(REQUIRED_ALIGNMENT);
                continue;
            }
            if (processedAddresses.contains(current)) {
                current = current.add(REQUIRED_ALIGNMENT);
                continue;
            }

            if (DEBUG_OUTPUT) {
                println("DEBUG: Checking alignment/padding patterns at address " + current);
            }
            
            // Look for repeating patterns of data followed by padding
            List<Integer> validPaddingSizes = new ArrayList<>();
            for (int structSize = MIN_STRUCT_SIZE; structSize <= MAX_STRUCT_SIZE;
                 structSize += REQUIRED_ALIGNMENT) {

                boolean hasPadding = hasPaddingPattern(current, structSize, blockEnd, addresses);
                
                if (DEBUG_OUTPUT) {
                    println("DEBUG:   Size " + structSize + " bytes: has padding pattern = " + hasPadding);
                }

                if (hasPadding) {
                    int count = countPaddingRepetitions(current, structSize, blockEnd, addresses);
                    
                    // Require more repetitions for smaller struct sizes to avoid false positives
                    int minRepsForSize = (structSize <= 8) ? MIN_REPETITIONS + 2 : MIN_REPETITIONS;

                    if (DEBUG_OUTPUT) {
                        println("DEBUG:   Size " + structSize + " bytes: " + count + " repetitions (min required: " + minRepsForSize + ")");
                    }

                    if (count >= minRepsForSize) {
                        validPaddingSizes.add(structSize);
                        if (DEBUG_OUTPUT) {
                            println("DEBUG:   ✓ ACCEPTED size " + structSize + " with " + count + " repetitions");
                        }
                    } else {
                        if (DEBUG_OUTPUT) {
                            //println("DEBUG:   ✗ REJECTED size " + structSize + " - insufficient repetitions");
                        }
                    }
                } else {
                    if (DEBUG_OUTPUT) {
                        //println("DEBUG:   ✗ REJECTED size " + structSize + " - no padding pattern");
                    }
                }
            }
            
            // Process valid padding sizes, but skip multiples of smaller valid sizes
            for (int structSize : validPaddingSizes) {
                // Skip if this size is a multiple of a smaller valid size
                boolean isMultipleOfSmaller = false;
                for (int smallerSize : validPaddingSizes) {
                    if (structSize != smallerSize && structSize % smallerSize == 0) {
                        isMultipleOfSmaller = true;
                        if (DEBUG_OUTPUT) {
                            println("DEBUG:   ✗ REJECTED size " + structSize + " - is a multiple of smaller size " + smallerSize);
                        }
                        break;
                    }
                }
                
                if (isMultipleOfSmaller) {
                    continue;
                }
                
                int count = countPaddingRepetitions(current, structSize, blockEnd, addresses);
                StructPattern pattern = new StructPattern(current, structSize, count);
                pattern.patternType = "Alignment/Padding Pattern";

                if (DEBUG_OUTPUT) {
                    println("DEBUG: Creating pattern - Type: " + pattern.patternType +
                           ", Address: " + current + ", Size: " + structSize + ", Count: " + count);
                }

                // Analyze the structure first
                analyzeStructureFields(pattern);
                
                // Calculate confidence with enhanced scoring (pattern type already reduces confidence)
                pattern.confidence = calculateConfidence(count, structSize, pattern.patternType,
                                                         pattern.fields, current, count);

                if (DEBUG_OUTPUT) {
                    println("DEBUG: Pattern confidence calculated: " + pattern.confidence + "%");
                    println("DEBUG: Fields detected: " + pattern.fields.size());
                    for (FieldInfo field : pattern.fields) {
                        println("DEBUG:   Field at offset 0x" + String.format("%02X", field.offset) +
                               ": " + field.description + " (" + field.size + " bytes)");
                    }
                }

                discoveredPatterns.add(pattern);

                break;
            }

            // Skip to the next unprocessed address
            current = current.add(REQUIRED_ALIGNMENT);
            while (current != null && current.compareTo(blockEnd) < 0 && processedAddresses.contains(current)) {
                current = current.add(1);
            }
        }
    }

    /**
     * Checks if there's a padding pattern at the given stride
     */
    private boolean hasPaddingPattern(Address start, int stride, Address endAddr, AddressSetView addresses) {
        try {
            Memory memory = currentProgram.getMemory();

            // Check for consistent null bytes or padding at end of structures
            for (int i = 0; i < MIN_REPETITIONS; i++) {
                Address checkAddr = start.add(i * stride + stride - REQUIRED_ALIGNMENT);
                if (checkAddr.compareTo(endAddr) > 0) {
                    return false;
                }
                
                // Skip addresses not in our target set
                if (!addresses.contains(checkAddr)) {
                    return false;
                }

                byte[] bytes = new byte[REQUIRED_ALIGNMENT];
                memory.getBytes(checkAddr, bytes);

                boolean hasNulls = false;
                for (byte b : bytes) {
                    if (b == 0) {
                        hasNulls = true;
                        break;
                    }
                }

                if (!hasNulls) {
                    return false;
                }
            }

            return true;

        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Counts padding pattern repetitions
     */
    private int countPaddingRepetitions(Address start, int stride, Address endAddr, AddressSetView addresses) {
        int count = 0;
        Address current = start;

        try {
            while (current != null && current.add(stride - 1).compareTo(endAddr) <= 0) {
                // Skip addresses not in our target set
                if (!addresses.contains(current)) {
                    current = current.add(stride);
                    continue;
                }
                
                if (hasPaddingAtEnd(current, stride)) {
                    count++;
                    current = current.add(stride);
                } else {
                    break;
                }
            }
        } catch (Exception e) {
            // Address error
        }

        return count;
    }

    /**
     * Checks if there's padding at the end of a potential struct
     */
    private boolean hasPaddingAtEnd(Address structStart, int structSize) {
        try {
            Memory memory = currentProgram.getMemory();
            Address paddingAddr = structStart.add(structSize - REQUIRED_ALIGNMENT);
            byte[] bytes = new byte[REQUIRED_ALIGNMENT];
            memory.getBytes(paddingAddr, bytes);

            for (byte b : bytes) {
                if (b == 0) {
                    return true;
                }
            }
            return false;

        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Strategy 4: Detect patterns using cross-reference analysis
     */
    private void detectCrossReferencePatterns(MemoryBlock block, AddressSetView addresses) {
        ReferenceManager refMgr = currentProgram.getReferenceManager();

        // Build a map of addresses and their reference counts
        Map<Address, List<Reference>> refMap = new HashMap<>();

        Address current = block.getStart();
        Address blockEnd = block.getEnd();

        while (current != null && current.compareTo(blockEnd) < 0) {
            // Skip addresses not in our target set
            if (!addresses.contains(current)) {
                current = current.add(1);
                continue;
            }
            ReferenceIterator refIter = refMgr.getReferencesTo(current);
            List<Reference> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                refs.add(refIter.next());
            }
            if (!refs.isEmpty()) {
                refMap.put(current, refs);
            }
            current = current.add(1);
        }

        // Analyze reference patterns to find arrays accessed with stride
        analyzeReferenceStrides(refMap, block, addresses);
    }

    /**
     * Analyzes reference patterns to find stride-based access
     */
    private void analyzeReferenceStrides(Map<Address, List<Reference>> refMap, MemoryBlock block, AddressSetView addresses) {
        // Group references by source function
        Map<Function, List<Address>> funcRefMap = new HashMap<>();

        for (Map.Entry<Address, List<Reference>> entry : refMap.entrySet()) {
            Address targetAddr = entry.getKey();

            for (Reference ref : entry.getValue()) {
                Function func = currentProgram.getFunctionManager()
                    .getFunctionContaining(ref.getFromAddress());
                if (func != null) {
                    funcRefMap.computeIfAbsent(func, k -> new ArrayList<>()).add(targetAddr);
                }
            }
        }

        // Look for regular stride patterns within each function's references
        for (Map.Entry<Function, List<Address>> entry : funcRefMap.entrySet()) {
            List<Address> refs = entry.getValue();
            if (refs.size() < MIN_REPETITIONS) {
                continue;
            }

            // Sort by address
            refs.sort(Address::compareTo);

            // Check for regular strides
            List<Long> strides = new ArrayList<>();
            for (int i = 1; i < refs.size(); i++) {
                long stride = refs.get(i).subtract(refs.get(i-1));
                strides.add(stride);
            }

            // Check if strides are consistent
            if (DEBUG_OUTPUT) {
                println("DEBUG: Checking cross-reference stride consistency for function " + entry.getKey().getName());
                println("DEBUG:   Strides: " + strides);
            }
            
            if (isConsistentStride(strides)) {
                long avgStride = strides.stream().mapToLong(Long::longValue).sum() / strides.size();

                if (DEBUG_OUTPUT) {
                    println("DEBUG:   ✓ Consistent strides found, average: " + avgStride);
                }

                if (avgStride >= MIN_STRUCT_SIZE && avgStride <= MAX_STRUCT_SIZE &&
                    avgStride % REQUIRED_ALIGNMENT == 0) {

                    Address startAddr = refs.get(0);
                    if (addresses.contains(startAddr)) {
                        // Check if there's already a pattern at this address with a smaller stride
                        boolean hasSmallerStridePattern = false;
                        for (StructPattern existingPattern : discoveredPatterns) {
                            if (existingPattern.startAddress.equals(startAddr) &&
                                existingPattern.structSize < avgStride &&
                                avgStride % existingPattern.structSize == 0) {
                                hasSmallerStridePattern = true;
                                if (DEBUG_OUTPUT) {
                                    println("DEBUG:   ✗ REJECTED - stride " + avgStride + " is a multiple of smaller stride " + existingPattern.structSize + " at same address");
                                }
                                break;
                            }
                        }
                        
                        if (!hasSmallerStridePattern) {
                            StructPattern pattern = new StructPattern(startAddr, (int)avgStride, refs.size());
                            pattern.patternType = "Cross-Reference Stride Access";

                            if (DEBUG_OUTPUT) {
                                println("DEBUG: Creating pattern - Type: " + pattern.patternType +
                                       ", Address: " + startAddr + ", Stride: " + avgStride + ", Count: " + refs.size());
                            }

                            // Analyze the structure first
                            analyzeStructureFields(pattern);
                            
                            // Calculate confidence with enhanced scoring (pattern type already gives bonus)
                            pattern.confidence = calculateConfidence(refs.size(), (int)avgStride, pattern.patternType,
                                                                   pattern.fields, startAddr, refs.size());

                            if (DEBUG_OUTPUT) {
                                println("DEBUG: Pattern confidence calculated: " + pattern.confidence + "%");
                                println("DEBUG: Fields detected: " + pattern.fields.size());
                                for (FieldInfo field : pattern.fields) {
                                    println("DEBUG:   Field at offset 0x" + String.format("%02X", field.offset) +
                                           ": " + field.description + " (" + field.size + " bytes)");
                                }
                            }

                            discoveredPatterns.add(pattern);
                        }
                    } else {
                        if (DEBUG_OUTPUT) {
                            println("DEBUG:   ✗ REJECTED - start address " + startAddr + " not in target address set");
                        }
                    }
                } else {
                    if (DEBUG_OUTPUT) {
                        println("DEBUG:   ✗ REJECTED - average stride " + avgStride + " out of range or not aligned");
                    }
                }
            } else {
                if (DEBUG_OUTPUT) {
                    println("DEBUG:   ✗ REJECTED - inconsistent strides");
                }
            }
        }
    }

    /**
     * Checks if a list of strides is consistent (similar values)
     */
    private boolean isConsistentStride(List<Long> strides) {
        if (strides.isEmpty()) {
            return false;
        }

        long first = strides.get(0);
        int consistentCount = 0;

        for (long stride : strides) {
            if (stride == first) {
                consistentCount++;
            }
        }

        // At least 80% should be the same stride
        return (consistentCount * 5) >= (strides.size() * 4);
    }

    /**
     * Analyzes the fields within a discovered struct pattern
     */
    private void analyzeStructureFields(StructPattern pattern) {
        try {
            Memory memory = currentProgram.getMemory();

            if (DEBUG_OUTPUT) {
                println("DEBUG: Analyzing fields for pattern at " + pattern.startAddress +
                       " (size: " + pattern.structSize + " bytes)");
            }

            // Analyze first instance of the struct
            for (int offset = 0; offset < pattern.structSize; offset += REQUIRED_ALIGNMENT) {
                Address fieldAddr = pattern.startAddress.add(offset);

                if (DEBUG_OUTPUT) {
                    println("DEBUG:   Analyzing field at offset 0x" + String.format("%02X", offset) +
                           " (address " + fieldAddr + ")");
                }

                // Check if it's a pointer
                if (isValidPointer(fieldAddr)) {
                    if (DEBUG_OUTPUT) {
                        println("DEBUG:     ✓ Valid pointer detected");
                    }
                    
                    // Determine what type of pointer it is by examining what it points to
                    Address targetAddr = getPointerTarget(fieldAddr);
                    if (targetAddr != null) {
                        // Check if pointer points to a string
                        if (isStringStart(targetAddr)) {
                            if (DEBUG_OUTPUT) {
                                println("DEBUG:     → Pointer points to string at " + targetAddr);
                            }
                            DataType ptrToStrType = new PointerDataType(new StringDataType(), currentProgram.getDataTypeManager());
                            pattern.fields.add(new FieldInfo(offset, ptrToStrType, POINTER_SIZE, "Pointer to String"));
                            continue;
                        }
                        
                        // Check if pointer points to code
                        if (isCodeAddress(targetAddr)) {
                            if (DEBUG_OUTPUT) {
                                println("DEBUG:     → Pointer points to code at " + targetAddr);
                            }
                            DataType ptrToCodeType = new PointerDataType(currentProgram.getDataTypeManager());
                            pattern.fields.add(new FieldInfo(offset, ptrToCodeType, POINTER_SIZE, "Pointer to Code"));
                            continue;
                        }
                        
                        // Check if pointer points to data
                        if (isDataAddress(targetAddr)) {
                            if (DEBUG_OUTPUT) {
                                println("DEBUG:     → Pointer points to data at " + targetAddr);
                            }
                            DataType ptrToDataType = new PointerDataType(currentProgram.getDataTypeManager());
                            pattern.fields.add(new FieldInfo(offset, ptrToDataType, POINTER_SIZE, "Pointer to Data"));
                            continue;
                        }
                        
                        if (DEBUG_OUTPUT) {
                            println("DEBUG:     → Pointer points to unknown location " + targetAddr);
                        }
                    } else {
                        if (DEBUG_OUTPUT) {
                            println("DEBUG:     → Pointer target could not be determined");
                        }
                    }
                    
                    // Generic pointer if we can't determine what it points to
                    DataType ptrType = new PointerDataType(currentProgram.getDataTypeManager());
                    pattern.fields.add(new FieldInfo(offset, ptrType, POINTER_SIZE, "Pointer"));
                    continue;
                } else {
                    if (DEBUG_OUTPUT) {
                        println("DEBUG:     ✗ Not a valid pointer");
                    }
                }

                // Check if it's a string (direct string, not a pointer to string)
                if (isStringStart(fieldAddr)) {
                    if (DEBUG_OUTPUT) {
                        println("DEBUG:     ✓ Direct string detected");
                    }
                    DataType strType = new StringDataType();
                    pattern.fields.add(new FieldInfo(offset, strType, -1, "String (variable)"));
                    continue;
                } else {
                    if (DEBUG_OUTPUT) {
                        println("DEBUG:     ✗ Not a string");
                    }
                }

                // Check for common integer sizes
                byte[] bytes = new byte[Math.min(8, pattern.structSize - offset)];
                memory.getBytes(fieldAddr, bytes);

                // Create appropriate undefined data type based on alignment
                DataType undefinedType;
                if (REQUIRED_ALIGNMENT == 2) {
                    undefinedType = new Undefined2DataType();
                } else if (REQUIRED_ALIGNMENT == 4) {
                    undefinedType = new Undefined4DataType();
                } else if (REQUIRED_ALIGNMENT == 8) {
                    undefinedType = new Undefined8DataType();
                } else {
                    undefinedType = new Undefined4DataType(); // Default fallback
                }
                
                if (DEBUG_OUTPUT) {
                    println("DEBUG:     → Undefined data (" + REQUIRED_ALIGNMENT + " bytes)");
                }
                
                // Check if the last field was also undefined and combine them
                if (!pattern.fields.isEmpty()) {
                    FieldInfo lastField = pattern.fields.get(pattern.fields.size() - 1);
                    if (lastField.description.equals("Undefined")) {
                        // Combine with the last undefined field
                        int combinedSize = lastField.size + REQUIRED_ALIGNMENT;
                        
                        // Limit combinations to 4 bytes maximum
                        if (combinedSize <= 4) {
                            if (DEBUG_OUTPUT) {
                                println("DEBUG:     → Combining with previous undefined field (total: " + combinedSize + " bytes)");
                            }
                            // Remove the last field and create a new combined one
                            pattern.fields.remove(pattern.fields.size() - 1);
                            
                            // Create appropriate combined undefined type
                            if (combinedSize == 2) {
                                undefinedType = new Undefined2DataType();
                            } else if (combinedSize == 4) {
                                undefinedType = new Undefined4DataType();
                            }
                            
                            pattern.fields.add(new FieldInfo(lastField.offset, undefinedType, combinedSize, "Undefined"));
                            continue; // Skip adding the new field as we've already added the combined one
                        }
                    }
                }
                
                pattern.fields.add(new FieldInfo(offset, undefinedType, REQUIRED_ALIGNMENT, "Undefined"));
            }

            if (DEBUG_OUTPUT) {
                println("DEBUG: Field analysis complete - found " + pattern.fields.size() + " fields");
            }

        } catch (Exception e) {
            if (VERBOSE_OUTPUT || DEBUG_OUTPUT) {
                println("Warning: Could not fully analyze fields for pattern at " + pattern.startAddress + ": " + e.getMessage());
            }
        }
    }

    /**
     * Checks if address points to start of a string
     */
    private boolean isStringStart(Address addr) {
        try {
            Memory memory = currentProgram.getMemory();
            byte[] bytes = new byte[Math.min(32, (int)memory.getSize())];
            int bytesRead = memory.getBytes(addr, bytes);

            int printableCount = 0;
            int nullIndex = -1;

            for (int i = 0; i < bytesRead; i++) {
                if (bytes[i] == 0) {
                    nullIndex = i;
                    break;
                }
                if ((bytes[i] >= 0x20 && bytes[i] <= 0x7E) || bytes[i] == '\t' || bytes[i] == '\n') {
                    printableCount++;
                }
            }

            // If we found a null terminator and most chars are printable
            return nullIndex > 0 && printableCount >= (nullIndex * 0.8);

        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Gets the target address of a pointer
     */
    private Address getPointerTarget(Address addr) {
        try {
            Memory memory = currentProgram.getMemory();
            byte[] bytes = new byte[POINTER_SIZE];
            memory.getBytes(addr, bytes);

            // Reconstruct pointer value
            long pointerValue = 0;
            boolean isLittleEndian = currentProgram.getLanguage().isBigEndian() == false;

            for (int i = 0; i < POINTER_SIZE; i++) {
                int byteIndex = isLittleEndian ? i : (POINTER_SIZE - 1 - i);
                pointerValue |= ((long)(bytes[byteIndex] & 0xFF)) << (i * 8);
            }

            // Check if pointer value is reasonable
            if (pointerValue == 0) {
                return null; // NULL pointer
            }

            // Try to create an address from the pointer value
            return currentProgram.getAddressFactory()
                .getDefaultAddressSpace().getAddress(pointerValue);

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Checks if an address points to code
     */
    private boolean isCodeAddress(Address addr) {
        try {
            Listing listing = currentProgram.getListing();
            Instruction instruction = listing.getInstructionAt(addr);
            if (instruction != null) {
                return true;
            }
            
            // Check if it's in a function
            Function function = currentProgram.getFunctionManager().getFunctionContaining(addr);
            if (function != null) {
                return true;
            }
            
            // Handle ARM thumb mode - check if address is odd (LSB=1 indicates thumb mode)
            // If odd, check the even address (actual instruction location)
            if (addr.getOffset() % 2 == 1) {
                Address evenAddr = addr.subtract(1);
                if (DEBUG_OUTPUT) {
                    println("DEBUG:     → Checking ARM thumb mode: odd address " + addr +
                           ", checking even address " + evenAddr);
                }
                
                // Check for instruction at the even address
                instruction = listing.getInstructionAt(evenAddr);
                if (instruction != null) {
                    if (DEBUG_OUTPUT) {
                        println("DEBUG:     → Found ARM thumb instruction at " + evenAddr +
                               " (referenced by odd address " + addr + ")");
                    }
                    return true;
                }
                
                // Check if even address is in a function
                function = currentProgram.getFunctionManager().getFunctionContaining(evenAddr);
                if (function != null) {
                    if (DEBUG_OUTPUT) {
                        println("DEBUG:     → Found ARM thumb function at " + evenAddr +
                               " (referenced by odd address " + addr + ")");
                    }
                    return true;
                }
            }
            
            return false;
            
        } catch (Exception e) {
            if (DEBUG_OUTPUT) {
                println("DEBUG:     → Exception checking code address: " + addr.toString() + " Error: " + e.getMessage());
            }
            return false;
        }
    }

    /**
     * Checks if an address points to data
     */
    private boolean isDataAddress(Address addr) {
        try {
            Memory memory = currentProgram.getMemory();
            if (!memory.contains(addr)) {
                return false;
            }
            
            // Check if it's not code and not a string
            if (isCodeAddress(addr) || isStringStart(addr)) {
                return false;
            }
            
            // Check if it's in a data memory block
            MemoryBlock block = memory.getBlock(addr);
            return block != null && block.isInitialized();
            
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Calculates confidence score for a pattern (enhanced version)
     */
    private int calculateConfidence(int repetitions, int structSize, String patternType,
                                   List<FieldInfo> fields, Address startAddress, int arrayCount) {
        // Weighted scoring system - each component contributes a specific percentage
        // Total weights should sum to 100
        final int PATTERN_TYPE_WEIGHT = 15;    // 15% of total score
        final int REPETITION_WEIGHT = 25;      // 25% of total score
        final int FIELD_ANALYSIS_WEIGHT = 20;  // 20% of total score
        final int MEMORY_CONTEXT_WEIGHT = 10;  // 10% of total score
        final int XREF_WEIGHT = 15;            // 15% of total score
        final int SIZE_WEIGHT = 5;             // 5% of total score
        final int ALIGNMENT_WEIGHT = 10;       // 10% of total score
        
        // Base score of 0, we'll build up from weighted components
        float weightedScore = 0;

        if (DEBUG_OUTPUT) {
            println("DEBUG: Calculating weighted confidence for pattern at " + startAddress);
        }

        // 1. Pattern type weighting (15% of total)
        int patternScore = getPatternTypeScore(patternType);
        float patternWeighted = (patternScore / 15.0f) * PATTERN_TYPE_WEIGHT;
        weightedScore += patternWeighted;
        if (DEBUG_OUTPUT) {
            println("DEBUG:   Pattern type '" + patternType + "': " + patternScore + "/15 → " +
                   String.format("%.1f", patternWeighted) + " (total: " + String.format("%.1f", weightedScore) + ")");
        }

        // 2. Repetition scoring (25% of total)
        int repetitionScore = getRepetitionScore(repetitions);
        float repetitionWeighted = (repetitionScore / 25.0f) * REPETITION_WEIGHT;
        weightedScore += repetitionWeighted;
        if (DEBUG_OUTPUT) {
            println("DEBUG:   Repetitions (" + repetitions + "): " + repetitionScore + "/25 → " +
                   String.format("%.1f", repetitionWeighted) + " (total: " + String.format("%.1f", weightedScore) + ")");
        }

        // 3. Field analysis confidence (20% of total)
        int fieldScore = getFieldAnalysisScore(fields);
        float fieldWeighted = (fieldScore / 20.0f) * FIELD_ANALYSIS_WEIGHT;
        weightedScore += fieldWeighted;
        if (DEBUG_OUTPUT) {
            println("DEBUG:   Field analysis: " + fieldScore + "/20 → " +
                   String.format("%.1f", fieldWeighted) + " (total: " + String.format("%.1f", weightedScore) + ")");
        }

        // 4. Memory context analysis (10% of total)
        int memoryScore = getMemoryContextScore(startAddress);
        float memoryWeighted = (memoryScore / 10.0f) * MEMORY_CONTEXT_WEIGHT;
        weightedScore += memoryWeighted;
        if (DEBUG_OUTPUT) {
            println("DEBUG:   Memory context: " + memoryScore + "/10 → " +
                   String.format("%.1f", memoryWeighted) + " (total: " + String.format("%.1f", weightedScore) + ")");
        }

        // 5. Cross-reference validation (15% of total)
        int xrefScore = getCrossReferenceScore(startAddress, structSize, arrayCount);
        float xrefWeighted = (xrefScore / 15.0f) * XREF_WEIGHT;
        weightedScore += xrefWeighted;
        if (DEBUG_OUTPUT) {
            println("DEBUG:   Cross-reference: " + xrefScore + "/15 → " +
                   String.format("%.1f", xrefWeighted) + " (total: " + String.format("%.1f", weightedScore) + ")");
        }

        // 6. Size distribution analysis (5% of total)
        int sizeScore = getSizeDistributionScore(structSize);
        float sizeWeighted = (sizeScore / 5.0f) * SIZE_WEIGHT;
        weightedScore += sizeWeighted;
        if (DEBUG_OUTPUT) {
            println("DEBUG:   Size distribution: " + sizeScore + "/5 → " +
                   String.format("%.1f", sizeWeighted) + " (total: " + String.format("%.1f", weightedScore) + ")");
        }

        // 7. Alignment and range checks (10% of total)
        int alignmentScore = getAlignmentScore(structSize);
        float alignmentWeighted = (alignmentScore / 10.0f) * ALIGNMENT_WEIGHT;
        weightedScore += alignmentWeighted;
        if (DEBUG_OUTPUT) {
            println("DEBUG:   Alignment: " + alignmentScore + "/10 → " +
                   String.format("%.1f", alignmentWeighted) + " (total: " + String.format("%.1f", weightedScore) + ")");
        }

        int finalScore = Math.max(0, Math.min(Math.round(weightedScore), 100));
        if (DEBUG_OUTPUT) {
            println("DEBUG:   Final weighted confidence score: " + finalScore + "%");
        }

        return finalScore;
    }

    /**
     * Gets confidence score based on pattern type
     */
    private int getPatternTypeScore(String patternType) {
        if (patternType == null) return 0;
        
        switch (patternType) {
            case "Cross-Reference Stride Access":
                return 15; // Most reliable (max score for this category)
            case "Evenly Spaced Pointers":
                return 10;
            case "Repeating Composite Sequence":
                return 8;
            case "Alignment/Padding Pattern":
                return 5; // Least reliable
            default:
                return 0;
        }
    }

    /**
     * Gets repetition score with diminishing returns
     */
    private int getRepetitionScore(int repetitions) {
        if (repetitions >= 20) {
            return 25; // Cap bonus for very high repetitions (max score for this category)
        } else if (repetitions >= 10) {
            return 20;
        } else if (repetitions >= 5) {
            return 15;
        } else if (repetitions >= 3) {
            return 10;
        }
        return 0;
    }

    /**
     * Analyzes field quality for confidence scoring
     */
    private int getFieldAnalysisScore(List<FieldInfo> fields) {
        if (fields == null || fields.isEmpty()) {
            return 0;
        }

        int pointerFields = 0;
        int stringFields = 0;
        int undefinedFields = 0;
        
        for (FieldInfo field : fields) {
            if (field.description.contains("Pointer")) {
                pointerFields++;
            } else if (field.description.contains("String")) {
                stringFields++;
            } else if (field.description.equals("Undefined")) {
                undefinedFields++;
            }
        }
        
        int score = 0;
        
        // More defined fields = higher confidence (max 15 points)
        int definedFields = pointerFields + stringFields;
        if (definedFields > 0) {
            score += Math.min(definedFields * 3, 15);
        }
        
        // Too many undefined fields reduces confidence (max penalty 10 points)
        if (undefinedFields > fields.size() * 0.7) {
            score -= 10;
        }
        
        // Bonus for mixed field types (suggests complex struct)
        if (pointerFields > 0 && (stringFields > 0 || undefinedFields > 0)) {
            score += 5;
        }
        
        // Ensure score is within expected range (0-20)
        return Math.max(0, Math.min(score, 20));
    }

    /**
     * Analyzes memory block properties for confidence scoring
     */
    private int getMemoryContextScore(Address startAddress) {
        int score = 0;
        
        try {
            MemoryBlock block = currentProgram.getMemory().getBlock(startAddress);
            if (block != null) {
                // Initialized blocks are more reliable
                if (block.isInitialized()) {
                    score += 5;
                }
                
                // Check if block has meaningful name (not auto-generated)
                if (!block.getName().matches(".+_\\d+")) {
                    score += 3;
                }
                
                // Read-only blocks suggest data structures
                if (block.isRead()) {
                    score += 2;
                }
                
                // Bonus for blocks in common data sections
                String blockName = block.getName().toLowerCase();
                if (blockName.contains(".data") || blockName.contains(".rodata") ||
                    blockName.contains(".rdata")) {
                    score += 3;
                }
            }
        } catch (Exception e) {
            // Ignore errors in memory analysis
        }
        
        // Ensure score is within expected range (0-10)
        return Math.max(0, Math.min(score, 10));
    }

    /**
     * Validates pattern using cross-reference analysis
     */
    private int getCrossReferenceScore(Address startAddress, int structSize, int arrayCount) {
        int score = 0;
        
        try {
            ReferenceManager refMgr = currentProgram.getReferenceManager();
            int referenceCount = 0;
            int firstElementRefCount = 0;
            boolean firstElementHasCodeRefs = false;
            
            // Check references to first few elements (limit for performance)
            int elementsToCheck = Math.min(arrayCount, 10);
            for (int i = 0; i < elementsToCheck; i++) {
                Address elementAddr = startAddress.add(i * structSize);
                ReferenceIterator refs = refMgr.getReferencesTo(elementAddr);
                int elementRefCount = 0;
                boolean elementHasCodeRefs = false;
                
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    referenceCount++;
                    elementRefCount++;
                    
                    if (isCodeAddress(ref.getFromAddress())) {
                        elementHasCodeRefs = true;
                    }
                }
                
                // Track first element references separately for bonus scoring
                if (i == 0) {
                    firstElementRefCount = elementRefCount;
                    firstElementHasCodeRefs = elementHasCodeRefs;
                }
            }
            
            // More references = higher confidence (max 10 points)
            if (referenceCount > 0) {
                score += Math.min(referenceCount * 2, 10);
            }
            
            // Bonus if references come from code (not data)
            if (referenceCount > 0) {
                boolean hasCodeReferences = false;
                for (int i = 0; i < elementsToCheck; i++) {
                    Address elementAddr = startAddress.add(i * structSize);
                    ReferenceIterator refs = refMgr.getReferencesTo(elementAddr);
                    while (refs.hasNext()) {
                        Reference ref = refs.next();
                        if (isCodeAddress(ref.getFromAddress())) {
                            hasCodeReferences = true;
                            break;
                        }
                    }
                    if (hasCodeReferences) break;
                }
                
                if (hasCodeReferences) {
                    score += 5;
                }
            }
            
            // ENHANCED: Additional bonus if first element has cross-references
            // This is a strong indicator that the array is actively used
            if (firstElementRefCount > 0) {
                // Give bonus points based on first element reference count
                int firstElementBonus = Math.min(firstElementRefCount * 3, 8);
                score += firstElementBonus;
                
                if (DEBUG_OUTPUT) {
                    println("DEBUG:   First element has " + firstElementRefCount + " references, bonus: +" + firstElementBonus);
                }
                
                // Extra bonus if first element has code references
                if (firstElementHasCodeRefs) {
                    score += 2;
                    if (DEBUG_OUTPUT) {
                        println("DEBUG:   First element has code references, extra bonus: +2");
                    }
                }
            }
            
        } catch (Exception e) {
            // Ignore errors in reference analysis
        }
        
        // Ensure score is within expected range (0-15)
        return Math.max(0, Math.min(score, 15));
    }

    /**
     * Analyzes size distribution for confidence scoring
     */
    private int getSizeDistributionScore(int structSize) {
        int score = 0;
        
        // Bonus for power-of-2 sizes
        if ((structSize & (structSize - 1)) == 0 && structSize > 0) {
            score += 3;
        }
        
        // Bonus for common struct sizes
        int[] commonSizes = {12, 16, 20, 24, 32, 40, 48, 64, 96, 128, 256};
        for (int commonSize : commonSizes) {
            if (structSize == commonSize) {
                score += 2;
                break;
            }
        }
        
        // Ensure score is within expected range (0-5)
        return Math.max(0, Math.min(score, 5));
    }

    /**
     * Gets alignment and range score (original logic)
     */
    private int getAlignmentScore(int structSize) {
        int score = 0;
        
        // Struct size aligned to common sizes = higher confidence
        if (structSize % 16 == 0) {
            score += 5;
        } else if (structSize % 8 == 0) {
            score += 3;
        }
        
        // Size in reasonable range
        if (structSize >= 16 && structSize <= 256) {
            score += 5;
        }
        
        // Ensure score is within expected range (0-10)
        return Math.max(0, Math.min(score, 10));
    }

    /**
     * Prints a discovered pattern to console
     */
    private void printPattern(StructPattern pattern) {
        println("========================================");
        println("Array of Structs Detected");
        println("========================================");
        println("Location: " + pattern.startAddress + " - " + 
               pattern.startAddress.add(pattern.structSize * pattern.arrayCount - 1));
        println("Struct Size: " + pattern.structSize + " bytes");
        println("Array Count: " + pattern.arrayCount + " elements");
        println("Confidence: " + getConfidenceLevel(pattern.confidence));
        println("");
        println("Detected Fields:");

        for (FieldInfo field : pattern.fields) {
            String sizeStr = field.size > 0 ? field.size + " bytes" : "variable";
            println("  [+0x" + String.format("%02X", field.offset) + "] " + 
                   field.description + " (" + sizeStr + ")");
        }

        println("");
        println("Pattern Match: " + pattern.patternType);
        println("Alignment: " + REQUIRED_ALIGNMENT + "-byte aligned");
        println("========================================\n");
    }

    /**
     * Converts numeric confidence to text level
     */
    private String getConfidenceLevel(int confidence) {
        if (confidence >= 80) return "HIGH (" + confidence + "%)";
        if (confidence >= 60) return "MEDIUM (" + confidence + "%)";
        return "LOW (" + confidence + "%)";
    }

    /**
     * Creates structure and array data types in Ghidra
     */
    private void createStructureAndArray(StructPattern pattern) {
        try {
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            int transactionId = currentProgram.startTransaction("Create Struct Array");

            try {
                // Create structure data type
                String structName = "struct_" + pattern.startAddress.toString().replace(":", "_") + 
                                  "_size_" + pattern.structSize;

                StructureDataType struct = new StructureDataType(structName, 0);

                // Add fields to structure
                int currentOffset = 0;
                for (FieldInfo field : pattern.fields) {
                    // Add padding if needed
                    while (currentOffset < field.offset) {
                        struct.add(DataType.DEFAULT);
                        currentOffset++;
                    }

                    // Add the field
                    if (field.size > 0) {
                        struct.add(field.dataType, field.size, "field_" + field.offset, null);
                        currentOffset += field.size;
                    }
                }

                // Pad to full struct size
                while (currentOffset < pattern.structSize) {
                    struct.add(DataType.DEFAULT);
                    currentOffset++;
                }

                // Add structure to data type manager
                DataType resolvedStruct = dtm.addDataType(struct, null);

                // Create array data type
                ArrayDataType arrayType = new ArrayDataType(resolvedStruct, pattern.arrayCount, 
                                                           pattern.structSize);

                // Apply array to memory
                Listing listing = currentProgram.getListing();
                listing.clearCodeUnits(pattern.startAddress, 
                                      pattern.startAddress.add((pattern.structSize * pattern.arrayCount) - 1),
                                      false);
                listing.createData(pattern.startAddress, arrayType);

                println("Successfully created structure '" + structName + "' and applied array at " + 
                       pattern.startAddress);

            } finally {
                currentProgram.endTransaction(transactionId, true);
            }

        } catch (Exception e) {
            println("Error creating structure for pattern at " + pattern.startAddress + ": " + 
                   e.getMessage());
            if (VERBOSE_OUTPUT) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Groups patterns by their starting address
     */
    private Map<Address, List<StructPattern>> groupPatternsByAddress(List<StructPattern> patterns) {
        Map<Address, List<StructPattern>> grouped = new HashMap<>();
        
        for (StructPattern pattern : patterns) {
            grouped.computeIfAbsent(pattern.startAddress, k -> new ArrayList<>()).add(pattern);
        }
        
        return grouped;
    }

    /**
     * Selects the best pattern for each address based on confidence, struct size, and repetitions
     */
    private List<StructPattern> selectBestPatterns(Map<Address, List<StructPattern>> patternsByAddress) {
        List<StructPattern> bestPatterns = new ArrayList<>();
        
        for (Map.Entry<Address, List<StructPattern>> entry : patternsByAddress.entrySet()) {
            Address address = entry.getKey();
            List<StructPattern> patterns = entry.getValue();
            
            if (patterns.isEmpty()) {
                continue;
            }
            
            if (DEBUG_OUTPUT) {
                println("DEBUG: Selecting best pattern for address " + address + " from " + patterns.size() + " candidates:");
                for (int i = 0; i < patterns.size(); i++) {
                    StructPattern p = patterns.get(i);
                    println("DEBUG:   Candidate " + (i+1) + ": " + p.patternType +
                           ", confidence=" + p.confidence + "%, size=" + p.structSize +
                           ", count=" + p.arrayCount);
                }
            }
            
            // Filter out patterns that are multiples of smaller patterns at the same address
            List<StructPattern> filteredPatterns = new ArrayList<>();
            for (StructPattern pattern : patterns) {
                boolean isMultipleOfSmaller = false;
                for (StructPattern otherPattern : patterns) {
                    if (pattern != otherPattern &&
                        pattern.structSize > otherPattern.structSize &&
                        pattern.structSize % otherPattern.structSize == 0) {
                        isMultipleOfSmaller = true;
                        if (DEBUG_OUTPUT) {
                            println("DEBUG:   ✗ FILTERING OUT pattern " + pattern.patternType +
                                   " (size " + pattern.structSize + ") - is a multiple of smaller pattern " +
                                   otherPattern.patternType + " (size " + otherPattern.structSize + ")");
                        }
                        break;
                    }
                }
                
                if (!isMultipleOfSmaller) {
                    filteredPatterns.add(pattern);
                }
            }
            
            if (DEBUG_OUTPUT && filteredPatterns.size() < patterns.size()) {
                println("DEBUG: Filtered " + (patterns.size() - filteredPatterns.size()) +
                       " patterns that were multiples of smaller patterns");
            }
            
            // Sort the filtered patterns by a composite score that considers:
            // 1. Confidence (primary factor)
            // 2. Number of repetitions (more is better)
            // 3. Struct size (smaller is generally better for efficiency)
            filteredPatterns.sort((p1, p2) -> {
                // Primary sort by confidence (descending)
                int confidenceCompare = Integer.compare(p2.confidence, p1.confidence);
                if (confidenceCompare != 0) {
                    return confidenceCompare;
                }
                
                // Secondary sort by repetitions (descending)
                int repetitionsCompare = Integer.compare(p2.arrayCount, p1.arrayCount);
                if (repetitionsCompare != 0) {
                    return repetitionsCompare;
                }
                
                // Tertiary sort by struct size (ascending - smaller is better)
                return Integer.compare(p1.structSize, p2.structSize);
            });
            
            // Select the best pattern (first in sorted list)
            StructPattern bestPattern = filteredPatterns.get(0);
            bestPatterns.add(bestPattern);
            
            if (DEBUG_OUTPUT || VERBOSE_OUTPUT) {
                println("DEBUG: Selected best pattern for address " + address +
                       ": " + bestPattern.patternType +
                       ", confidence=" + bestPattern.confidence + "%" +
                       ", repetitions=" + bestPattern.arrayCount +
                       ", size=" + bestPattern.structSize);
                
                if (filteredPatterns.size() > 1) {
                    println("DEBUG: Discarded " + (filteredPatterns.size() - 1) + " other filtered patterns:");
                    for (int i = 1; i < filteredPatterns.size(); i++) {
                        StructPattern discarded = filteredPatterns.get(i);
                        println("DEBUG:   Discarded: " + discarded.patternType +
                               ", confidence=" + discarded.confidence + "%" +
                               ", size=" + discarded.structSize +
                               ", count=" + discarded.arrayCount);
                    }
                }
            }
        }
        
        return bestPatterns;
    }

    /**
     * Marks all addresses covered by the selected patterns as processed
     * This prevents overlapping structures from being created
     */
    private void markAddressesAsProcessed(List<StructPattern> patterns) {
        for (StructPattern pattern : patterns) {
            // Mark ALL addresses in the entire array as processed
            for (int i = 0; i < pattern.arrayCount; i++) {
                Address elementStart = pattern.startAddress.add(i * pattern.structSize);
                // Mark every byte within each struct element as processed
                for (int offset = 0; offset < pattern.structSize; offset++) {
                    try {
                        processedAddresses.add(elementStart.add(offset));
                    } catch (Exception e) {
                        // Skip if address calculation fails
                    }
                }
            }
            
            if (VERBOSE_OUTPUT) {
                println("Marked " + (pattern.structSize * pattern.arrayCount) +
                       " bytes as processed for pattern at " + pattern.startAddress);
            }
        }
    }
}
