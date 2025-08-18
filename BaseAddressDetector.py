# Base Address Detection Script for Ghidra
# Author: mobilemutex
# Description: Comprehensive script to automatically detect base addresses for firmware files
#              using multiple heuristic methods and architecture-specific analysis

from ghidra.program.model.address import Address
from ghidra.program.model.listing import Instruction
from ghidra.program.model.symbol import SymbolUtilities
from ghidra.program.model.mem import Memory, MemoryBlock
from ghidra.app.util import Option
from ghidra.util.task import TaskMonitor
from java.util import ArrayList
import re
import struct

class BaseAddressResult:
    """Container for base address detection results"""
    def __init__(self, address, confidence, method_scores, firmware_start_offset=0, architecture=None):
        self.address = address
        self.confidence = confidence
        self.method_scores = method_scores
        self.firmware_start_offset = firmware_start_offset
        self.architecture = architecture
        self.notes = []

class ArchitectureAnalyzer:
    """Detect and analyze architecture-specific patterns"""
    
    def __init__(self, program):
        self.program = program
        self.processor = program.getLanguage().getProcessor().toString()
        
    def get_architecture(self):
        """Detect the target architecture"""
        processor = self.processor.lower()
        if 'mips' in processor:
            return 'MIPS'
        elif 'arm' in processor or 'thumb' in processor:
            return 'ARM'
        elif 'x86' in processor or 'amd64' in processor:
            return 'x86'
        else:
            return 'UNKNOWN'
    
    def get_pointer_size(self):
        """Get the pointer size for the architecture"""
        return self.program.getDefaultPointerSize()
    
    def get_alignment(self):
        """Get typical alignment for the architecture"""
        arch = self.get_architecture()
        if arch == 'MIPS':
            return 4
        elif arch == 'ARM':
            return 4
        elif arch == 'x86':
            return self.get_pointer_size()
        else:
            return 4

class PointerExtractor:
    """Extract potential pointer values from instructions and data"""
    
    def __init__(self, program, arch_analyzer):
        self.program = program
        self.arch_analyzer = arch_analyzer
        self.listing = program.getListing()
        self.memory = program.getMemory()
        
    def extract_instruction_pointers(self):
        """Extract potential pointers from instruction operands"""
        pointers = []
        instruction_iter = self.listing.getInstructions(True)
        
        for instruction in instruction_iter:
            # Get instruction operands
            for i in range(instruction.getNumOperands()):
                operand = instruction.getOpObjects(i)
                for op in operand:
                    # Check for address operands
                    if hasattr(op, 'getOffset'):
                        offset = op.getOffset()
                        if self._is_valid_pointer(offset):
                            pointers.append(offset)
                    # Check for scalar operands (immediate values)
                    elif hasattr(op, 'getValue'):
                        value = op.getValue()
                        if self._is_valid_pointer(value):
                            pointers.append(value)
        
        return pointers
    
    def extract_data_pointers(self):
        """Extract potential pointers from data sections"""
        pointers = []
        pointer_size = self.arch_analyzer.get_pointer_size()
        
        # Iterate through memory blocks
        for block in self.memory.getBlocks():
            if not block.isExecute():  # Focus on data blocks
                addr = block.getStart()
                end_addr = block.getEnd()
                
                while addr.compareTo(end_addr) < 0:
                    try:
                        # Read pointer-sized value
                        if pointer_size == 4:
                            value = self.memory.getInt(addr) & 0xFFFFFFFF
                        else:
                            value = self.memory.getLong(addr) & 0xFFFFFFFFFFFFFFFF
                        
                        if self._is_valid_pointer(value):
                            pointers.append(value)
                        
                        addr = addr.add(pointer_size)
                    except:
                        addr = addr.add(1)
        
        return pointers
    
    def _is_valid_pointer(self, value):
        """Check if a value could be a valid pointer"""
        if value is None:
            return False
        
        # Convert to long if needed
        if hasattr(value, 'longValue'):
            value = value.longValue()
        
        # Basic sanity checks
        if value < 0x1000:  # Too small
            return False
        if value > 0xFFFFFFFFFFFFFFFF:  # Too large
            return False
        
        # Architecture-specific checks
        arch = self.arch_analyzer.get_architecture()
        if arch == 'MIPS':
            # MIPS typically uses specific address ranges
            return (0x80000000 <= value <= 0xBFFFFFFF) or (0x00000000 <= value <= 0x7FFFFFFF)
        elif arch == 'ARM':
            # ARM address ranges
            return value <= 0xFFFFFFFF
        elif arch == 'x86':
            pointer_size = self.arch_analyzer.get_pointer_size()
            if pointer_size == 4:
                return value <= 0xFFFFFFFF
            else:
                return True  # 64-bit can use full range
        
        return True

class StringAnalyzer:
    """Analyze string references for base address detection"""
    
    def __init__(self, program):
        self.program = program
        self.listing = program.getListing()
        self.memory = program.getMemory()
        
    def find_strings(self, min_length=4):
        """Find string literals in the program"""
        strings = []
        
        # Get defined strings from Ghidra
        data_iter = self.listing.getDefinedData(True)
        for data in data_iter:
            if data.hasStringValue():
                string_value = data.getValue()
                if len(str(string_value)) >= min_length:
                    strings.append({
                        'address': data.getAddress().getOffset(),
                        'value': str(string_value),
                        'length': len(str(string_value))
                    })
        
        # Also scan for undefined strings
        strings.extend(self._scan_undefined_strings(min_length))
        
        return strings
    
    def _scan_undefined_strings(self, min_length):
        """Scan for strings not yet defined by Ghidra"""
        strings = []
        
        for block in self.memory.getBlocks():
            if not block.isExecute():  # Focus on data blocks
                addr = block.getStart()
                end_addr = block.getEnd()
                
                current_string = ""
                string_start = None
                
                while addr.compareTo(end_addr) < 0:
                    try:
                        byte_val = self.memory.getByte(addr) & 0xFF
                        
                        if 32 <= byte_val <= 126:  # Printable ASCII
                            if string_start is None:
                                string_start = addr.getOffset()
                            current_string += chr(byte_val)
                        else:
                            if len(current_string) >= min_length:
                                strings.append({
                                    'address': string_start,
                                    'value': current_string,
                                    'length': len(current_string)
                                })
                            current_string = ""
                            string_start = None
                        
                        addr = addr.add(1)
                    except:
                        addr = addr.add(1)
        
        return strings
    
    def find_string_references(self, strings):
        """Find instructions that reference the given strings"""
        references = []
        
        for string_info in strings:
            string_addr = string_info['address']
            
            # Look for references to this address
            refs = self.program.getReferenceManager().getReferencesTo(
                self.program.getAddressFactory().getAddress(hex(string_addr))
            )
            
            for ref in refs:
                references.append({
                    'string_address': string_addr,
                    'reference_address': ref.getFromAddress().getOffset(),
                    'string_value': string_info['value']
                })
        
        return references

class MIPSAnalyzer:
    """MIPS-specific instruction pattern analysis"""
    
    def __init__(self, program):
        self.program = program
        self.listing = program.getListing()
        
    def find_lui_ori_pairs(self):
        """Find LUI-ORI instruction pairs that load 32-bit addresses"""
        pairs = []
        instruction_iter = self.listing.getInstructions(True)
        
        prev_instruction = None
        for instruction in instruction_iter:
            if prev_instruction is not None:
                # Check for LUI followed by ORI
                if (prev_instruction.getMnemonicString() == "lui" and 
                    instruction.getMnemonicString() == "ori"):
                    
                    # Extract the 32-bit address
                    lui_imm = self._get_immediate_value(prev_instruction)
                    ori_imm = self._get_immediate_value(instruction)
                    
                    if lui_imm is not None and ori_imm is not None:
                        full_address = (lui_imm << 16) | ori_imm
                        pairs.append({
                            'address': full_address,
                            'lui_addr': prev_instruction.getAddress().getOffset(),
                            'ori_addr': instruction.getAddress().getOffset()
                        })
            
            prev_instruction = instruction
        
        return pairs
    
    def find_lui_addiu_pairs(self):
        """Find LUI-ADDIU instruction pairs"""
        pairs = []
        instruction_iter = self.listing.getInstructions(True)
        
        prev_instruction = None
        for instruction in instruction_iter:
            if prev_instruction is not None:
                if (prev_instruction.getMnemonicString() == "lui" and 
                    instruction.getMnemonicString() == "addiu"):
                    
                    lui_imm = self._get_immediate_value(prev_instruction)
                    addiu_imm = self._get_immediate_value(instruction)
                    
                    if lui_imm is not None and addiu_imm is not None:
                        # Handle sign extension for addiu
                        if addiu_imm > 0x7FFF:
                            addiu_imm = addiu_imm - 0x10000
                        
                        full_address = (lui_imm << 16) + addiu_imm
                        pairs.append({
                            'address': full_address & 0xFFFFFFFF,
                            'lui_addr': prev_instruction.getAddress().getOffset(),
                            'addiu_addr': instruction.getAddress().getOffset()
                        })
            
            prev_instruction = instruction
        
        return pairs
    
    def _get_immediate_value(self, instruction):
        """Extract immediate value from MIPS instruction"""
        try:
            # Get the last operand which is typically the immediate
            num_operands = instruction.getNumOperands()
            if num_operands > 0:
                operand = instruction.getOpObjects(num_operands - 1)[0]
                if hasattr(operand, 'getValue'):
                    return operand.getValue() & 0xFFFF
        except:
            pass
        return None

class StatisticalAnalyzer:
    """Perform statistical analysis and clustering of potential addresses"""
    
    def __init__(self, program, arch_analyzer):
        self.program = program
        self.arch_analyzer = arch_analyzer
        
    def cluster_addresses(self, addresses, file_size):
        """Cluster addresses by proximity"""
        if not addresses:
            return []
        
        # Sort addresses
        sorted_addresses = sorted(set(addresses))
        
        # Determine cluster range based on file size
        cluster_range = max(file_size, 0x10000)
        
        clusters = []
        current_cluster = [sorted_addresses[0]]
        
        for addr in sorted_addresses[1:]:
            if addr - current_cluster[-1] <= cluster_range:
                current_cluster.append(addr)
            else:
                if len(current_cluster) >= 3:  # Minimum cluster size
                    clusters.append(current_cluster)
                current_cluster = [addr]
        
        # Add the last cluster
        if len(current_cluster) >= 3:
            clusters.append(current_cluster)
        
        return clusters
    
    def calculate_search_ranges(self, clusters, file_size):
        """Calculate base address search ranges from clusters"""
        search_ranges = []
        alignment = self.arch_analyzer.get_alignment()
        
        for cluster in clusters:
            min_addr = min(cluster)
            max_addr = max(cluster)
            
            # Calculate potential base address range
            range_start = (min_addr - file_size) & ~(alignment - 1)
            range_end = max_addr & ~(alignment - 1)
            
            if range_start < range_end:
                search_ranges.append((range_start, range_end))
        
        return search_ranges
    
    def score_base_address(self, base_address, pointers, strings, file_size):
        """Score a candidate base address"""
        scores = {
            'pointer_alignment': 0.0,
            'string_reference': 0.0,
            'address_density': 0.0
        }
        
        # Score pointer alignment
        valid_pointers = 0
        for pointer in pointers:
            file_offset = pointer - base_address
            if 0 <= file_offset < file_size:
                valid_pointers += 1
        
        if pointers:
            scores['pointer_alignment'] = float(valid_pointers) / len(pointers)
        
        # Score string references
        valid_string_refs = 0
        for string_info in strings:
            string_file_offset = string_info['address'] - base_address
            if 0 <= string_file_offset < file_size:
                valid_string_refs += 1
        
        if strings:
            scores['string_reference'] = float(valid_string_refs) / len(strings)
        
        # Score address density (how many addresses fall in valid range)
        all_addresses = pointers + [s['address'] for s in strings]
        valid_addresses = sum(1 for addr in all_addresses 
                            if 0 <= addr - base_address < file_size)
        
        if all_addresses:
            scores['address_density'] = float(valid_addresses) / len(all_addresses)
        
        return scores

class FirmwareAnalyzer:
    """Analyze firmware structure and detect headers"""
    
    def __init__(self, program):
        self.program = program
        self.memory = program.getMemory()
        
    def detect_firmware_start(self):
        """Detect the actual start of firmware code"""
        # Get the first memory block
        first_block = None
        for block in self.memory.getBlocks():
            if first_block is None or block.getStart().compareTo(first_block.getStart()) < 0:
                first_block = block
        
        if first_block is None:
            return 0
        
        start_addr = first_block.getStart()
        
        # Check for common firmware headers
        header_offset = self._check_common_headers(start_addr)
        if header_offset > 0:
            return header_offset
        
        # Analyze instruction density to find code start
        code_start = self._find_code_start(start_addr)
        return code_start
    
    def _check_common_headers(self, start_addr):
        """Check for common firmware header patterns"""
        try:
            # Read first 64 bytes
            header_data = []
            for i in range(64):
                try:
                    byte_val = self.memory.getByte(start_addr.add(i)) & 0xFF
                    header_data.append(byte_val)
                except:
                    break
            
            if len(header_data) < 16:
                return 0
            
            # Check for ELF header
            if header_data[:4] == [0x7F, 0x45, 0x4C, 0x46]:  # ELF magic
                return 0  # ELF files don't need offset detection
            
            # Check for common firmware magic numbers
            magic_patterns = [
                [0x27, 0x05, 0x19, 0x56],  # U-Boot
                [0x56, 0x19, 0x05, 0x27],  # U-Boot (reversed)
                [0x00, 0x00, 0x00, 0x00],  # Padding pattern
            ]
            
            for i, pattern in enumerate(magic_patterns):
                if header_data[:len(pattern)] == pattern:
                    # Found header, look for code start after it
                    return self._find_code_after_offset(start_addr, 64)
            
        except:
            pass
        
        return 0
    
    def _find_code_start(self, start_addr):
        """Find the start of actual code by analyzing instruction density"""
        max_scan = min(0x1000, self.memory.getSize())  # Scan first 4KB
        best_offset = 0
        best_score = 0
        
        # Scan in 16-byte increments
        for offset in range(0, max_scan, 16):
            try:
                addr = start_addr.add(offset)
                score = self._calculate_instruction_density(addr, 256)
                
                if score > best_score:
                    best_score = score
                    best_offset = offset
                    
            except:
                continue
        
        return best_offset
    
    def _find_code_after_offset(self, start_addr, min_offset):
        """Find code start after a minimum offset"""
        max_scan = min(0x2000, self.memory.getSize())
        
        for offset in range(min_offset, max_scan, 4):
            try:
                addr = start_addr.add(offset)
                score = self._calculate_instruction_density(addr, 128)
                
                if score > 0.5:  # Good instruction density
                    return offset
                    
            except:
                continue
        
        return min_offset
    
    def _calculate_instruction_density(self, addr, scan_length):
        """Calculate the density of valid instructions at an address"""
        valid_instructions = 0
        total_checked = 0
        
        current_addr = addr
        end_addr = addr.add(scan_length)
        
        while current_addr.compareTo(end_addr) < 0:
            try:
                instruction = self.program.getListing().getInstructionAt(current_addr)
                if instruction is not None:
                    valid_instructions += 1
                total_checked += 1
                current_addr = current_addr.add(4)  # Assume 4-byte instructions
            except:
                current_addr = current_addr.add(1)
                total_checked += 1
        
        return float(valid_instructions) / max(total_checked, 1)

class BaseAddressDetector:
    """Main class for base address detection"""
    
    def __init__(self, program):
        self.program = program
        self.arch_analyzer = ArchitectureAnalyzer(program)
        self.pointer_extractor = PointerExtractor(program, self.arch_analyzer)
        self.string_analyzer = StringAnalyzer(program)
        self.statistical_analyzer = StatisticalAnalyzer(program, self.arch_analyzer)
        self.firmware_analyzer = FirmwareAnalyzer(program)
        
        # Initialize architecture-specific analyzers
        arch = self.arch_analyzer.get_architecture()
        if arch == 'MIPS':
            self.arch_specific = MIPSAnalyzer(program)
        else:
            self.arch_specific = None
    
    def detect_base_address(self, config=None):
        """Main method to detect base address"""
        if config is None:
            config = self._get_default_config()
        
        print("Starting base address detection...")
        print("Architecture: {}".format(self.arch_analyzer.get_architecture()))
        
        # Step 1: Analyze firmware structure
        firmware_start_offset = self.firmware_analyzer.detect_firmware_start()
        print("Firmware start offset: 0x{:X}".format(firmware_start_offset))
        
        # Step 2: Extract potential pointers
        print("Extracting pointers from instructions...")
        instruction_pointers = self.pointer_extractor.extract_instruction_pointers()
        print("Found {} instruction pointers".format(len(instruction_pointers)))
        
        print("Extracting pointers from data...")
        data_pointers = self.pointer_extractor.extract_data_pointers()
        print("Found {} data pointers".format(len(data_pointers)))
        
        all_pointers = instruction_pointers + data_pointers
        
        # Step 3: Architecture-specific analysis
        arch_pointers = []
        if self.arch_specific:
            print("Performing architecture-specific analysis...")
            if hasattr(self.arch_specific, 'find_lui_ori_pairs'):
                lui_ori_pairs = self.arch_specific.find_lui_ori_pairs()
                arch_pointers.extend([pair['address'] for pair in lui_ori_pairs])
                print("Found {} LUI-ORI pairs".format(len(lui_ori_pairs)))
            
            if hasattr(self.arch_specific, 'find_lui_addiu_pairs'):
                lui_addiu_pairs = self.arch_specific.find_lui_addiu_pairs()
                arch_pointers.extend([pair['address'] for pair in lui_addiu_pairs])
                print("Found {} LUI-ADDIU pairs".format(len(lui_addiu_pairs)))
        
        all_pointers.extend(arch_pointers)
        
        # Step 4: String analysis
        print("Analyzing strings...")
        strings = self.string_analyzer.find_strings(config.get('min_string_length', 4))
        print("Found {} strings".format(len(strings)))
        
        # Step 5: Statistical analysis
        print("Performing statistical analysis...")
        file_size = self._get_file_size()
        clusters = self.statistical_analyzer.cluster_addresses(all_pointers, file_size)
        print("Found {} address clusters".format(len(clusters)))
        
        search_ranges = self.statistical_analyzer.calculate_search_ranges(clusters, file_size)
        print("Calculated {} search ranges".format(len(search_ranges)))
        
        # Step 6: Score candidate base addresses
        candidates = []
        alignment = self.arch_analyzer.get_alignment()
        
        for range_start, range_end in search_ranges:
            for base_addr in range(range_start, range_end + 1, alignment):
                if config.get('min_base_address', 0) <= base_addr <= config.get('max_base_address', 0xFFFFFFFF):
                    scores = self.statistical_analyzer.score_base_address(
                        base_addr, all_pointers, strings, file_size
                    )
                    
                    # Calculate overall confidence
                    confidence = (
                        scores['pointer_alignment'] * 0.4 +
                        scores['string_reference'] * 0.3 +
                        scores['address_density'] * 0.3
                    )
                    
                    if confidence > config.get('min_confidence', 0.1):
                        result = BaseAddressResult(
                            base_addr, confidence, scores, 
                            firmware_start_offset, self.arch_analyzer.get_architecture()
                        )
                        candidates.append(result)
        
        # Sort by confidence
        candidates.sort(key=lambda x: x.confidence, reverse=True)
        
        # Return top candidates
        max_results = config.get('max_results', 10)
        return candidates[:max_results]
    
    def _get_default_config(self):
        """Get default configuration"""
        return {
            'min_string_length': 4,
            'min_base_address': 0x00000000,
            'max_base_address': 0xFFFFFFFF,
            'min_confidence': 0.1,
            'max_results': 10
        }
    
    def _get_file_size(self):
        """Get the size of the loaded file"""
        total_size = 0
        for block in self.program.getMemory().getBlocks():
            total_size += block.getSize()
        return total_size

def main():
    """Main script execution"""
    if currentProgram is None:
        print("No program loaded. Please load a firmware file first.")
        return
    
    print("=" * 60)
    print("Base Address Detection Script")
    print("Author: mobilemutex")
    print("=" * 60)
    
    # Create detector
    detector = BaseAddressDetector(currentProgram)
    
    # Run detection
    results = detector.detect_base_address()
    
    # Display results
    print("\nDetection Results:")
    print("-" * 40)
    
    if not results:
        print("No candidate base addresses found.")
        print("This may indicate:")
        print("- The firmware uses position-independent code")
        print("- The firmware is encrypted or compressed")
        print("- The detection methods need adjustment")
        return
    
    for i, result in enumerate(results):
        print("Candidate #{}: 0x{:08X}".format(i + 1, result.address))
        print("  Confidence: {:.2%}".format(result.confidence))
        print("  Architecture: {}".format(result.architecture))
        print("  Firmware Start Offset: 0x{:X}".format(result.firmware_start_offset))
        print("  Method Scores:")
        for method, score in result.method_scores.items():
            print("    {}: {:.2%}".format(method, score))
        print()
    
    # Provide recommendations
    if results:
        best_result = results[0]
        print("Recommendation:")
        print("Use base address 0x{:08X} with confidence {:.2%}".format(
            best_result.address, best_result.confidence))
        
        if best_result.firmware_start_offset > 0:
            print("Note: Firmware appears to start at offset 0x{:X} in the file".format(
                best_result.firmware_start_offset))
        
        if best_result.confidence < 0.5:
            print("Warning: Low confidence result. Manual verification recommended.")

if __name__ == "__main__":
    main()

