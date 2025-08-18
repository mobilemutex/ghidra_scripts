# Advanced Base Address Detection Script for Ghidra
# Author: mobilemutex
# Description: Enhanced version with ARM support, entropy analysis, and advanced heuristics

from ghidra.program.model.address import Address
from ghidra.program.model.listing import Instruction
from ghidra.program.model.symbol import SymbolUtilities
from ghidra.program.model.mem import Memory, MemoryBlock
from ghidra.app.util import Option
from ghidra.util.task import TaskMonitor
from java.util import ArrayList
import re
import struct
import math

class ARMAnalyzer:
    """ARM-specific instruction pattern analysis"""
    
    def __init__(self, program):
        self.program = program
        self.listing = program.getListing()
        
    def find_literal_pools(self):
        """Find ARM literal pools and their references"""
        pools = []
        instruction_iter = self.listing.getInstructions(True)
        
        for instruction in instruction_iter:
            mnemonic = instruction.getMnemonicString().lower()
            
            # Look for LDR instructions with PC-relative addressing
            if mnemonic.startswith('ldr'):
                operands = instruction.getOpObjects(1)  # Second operand
                for operand in operands:
                    if hasattr(operand, 'getAddress'):
                        target_addr = operand.getAddress().getOffset()
                        pools.append({
                            'pool_address': target_addr,
                            'reference_address': instruction.getAddress().getOffset(),
                            'instruction': str(instruction)
                        })
        
        return pools
    
    def find_function_prologues(self):
        """Find ARM function prologue patterns"""
        prologues = []
        instruction_iter = self.listing.getInstructions(True)
        
        prev_instructions = []
        for instruction in instruction_iter:
            mnemonic = instruction.getMnemonicString().lower()
            
            # Common ARM prologue patterns
            if mnemonic in ['push', 'stmfd', 'str'] and 'lr' in str(instruction).lower():
                prologues.append({
                    'address': instruction.getAddress().getOffset(),
                    'pattern': 'lr_save',
                    'instruction': str(instruction)
                })
            elif mnemonic == 'mov' and 'fp' in str(instruction).lower():
                prologues.append({
                    'address': instruction.getAddress().getOffset(),
                    'pattern': 'fp_setup',
                    'instruction': str(instruction)
                })
            
            # Keep track of recent instructions for pattern matching
            prev_instructions.append(instruction)
            if len(prev_instructions) > 3:
                prev_instructions.pop(0)
        
        return prologues
    
    def analyze_branch_targets(self):
        """Analyze branch and call targets"""
        targets = []
        instruction_iter = self.listing.getInstructions(True)
        
        for instruction in instruction_iter:
            mnemonic = instruction.getMnemonicString().lower()
            
            # Look for branch instructions
            if mnemonic.startswith('b') or mnemonic.startswith('bl'):
                # Get branch target
                for i in range(instruction.getNumOperands()):
                    operand = instruction.getOpObjects(i)[0]
                    if hasattr(operand, 'getOffset'):
                        target = operand.getOffset()
                        targets.append({
                            'target_address': target,
                            'source_address': instruction.getAddress().getOffset(),
                            'type': 'call' if 'l' in mnemonic else 'branch'
                        })
        
        return targets

class x86Analyzer:
    """x86/x64-specific instruction pattern analysis"""
    
    def __init__(self, program):
        self.program = program
        self.listing = program.getListing()
        
    def find_direct_addresses(self):
        """Find direct address references in x86 code"""
        addresses = []
        instruction_iter = self.listing.getInstructions(True)
        
        for instruction in instruction_iter:
            # Look for instructions with direct memory operands
            for i in range(instruction.getNumOperands()):
                operand = instruction.getOpObjects(i)
                for op in operand:
                    if hasattr(op, 'getAddress'):
                        addr = op.getAddress().getOffset()
                        addresses.append({
                            'address': addr,
                            'instruction_addr': instruction.getAddress().getOffset(),
                            'instruction': str(instruction)
                        })
        
        return addresses
    
    def find_call_targets(self):
        """Find call instruction targets"""
        targets = []
        instruction_iter = self.listing.getInstructions(True)
        
        for instruction in instruction_iter:
            mnemonic = instruction.getMnemonicString().lower()
            
            if mnemonic == 'call':
                # Get call target
                if instruction.getNumOperands() > 0:
                    operand = instruction.getOpObjects(0)[0]
                    if hasattr(operand, 'getOffset'):
                        target = operand.getOffset()
                        targets.append({
                            'target_address': target,
                            'source_address': instruction.getAddress().getOffset()
                        })
        
        return targets

class EntropyAnalyzer:
    """Analyze entropy to detect compressed/encrypted sections"""
    
    def __init__(self, program):
        self.program = program
        self.memory = program.getMemory()
        
    def calculate_entropy(self, start_addr, length):
        """Calculate Shannon entropy for a memory region"""
        byte_counts = [0] * 256
        total_bytes = 0
        
        try:
            for i in range(length):
                byte_val = self.memory.getByte(start_addr.add(i)) & 0xFF
                byte_counts[byte_val] += 1
                total_bytes += 1
        except:
            pass
        
        if total_bytes == 0:
            return 0.0
        
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                probability = float(count) / total_bytes
                entropy -= probability * math.log(probability, 2)
        
        return entropy
    
    def find_low_entropy_regions(self, block_size=1024, threshold=6.0):
        """Find regions with low entropy (likely code or structured data)"""
        regions = []
        
        for block in self.memory.getBlocks():
            addr = block.getStart()
            end_addr = block.getEnd()
            
            while addr.add(block_size).compareTo(end_addr) <= 0:
                entropy = self.calculate_entropy(addr, block_size)
                
                if entropy < threshold:
                    regions.append({
                        'start_address': addr.getOffset(),
                        'size': block_size,
                        'entropy': entropy
                    })
                
                addr = addr.add(block_size // 2)  # Overlapping windows
        
        return regions

class CrossReferenceAnalyzer:
    """Analyze cross-references for base address detection"""
    
    def __init__(self, program):
        self.program = program
        self.ref_manager = program.getReferenceManager()
        
    def analyze_reference_patterns(self):
        """Analyze patterns in cross-references"""
        patterns = {
            'function_calls': [],
            'data_references': [],
            'string_references': []
        }
        
        # Get all references
        all_refs = self.ref_manager.getReferenceIterator()
        
        for ref in all_refs:
            from_addr = ref.getFromAddress().getOffset()
            to_addr = ref.getToAddress().getOffset()
            ref_type = ref.getReferenceType()
            
            if ref_type.isCall():
                patterns['function_calls'].append({
                    'from': from_addr,
                    'to': to_addr,
                    'type': 'call'
                })
            elif ref_type.isData():
                patterns['data_references'].append({
                    'from': from_addr,
                    'to': to_addr,
                    'type': 'data'
                })
        
        return patterns
    
    def find_reference_clusters(self, references):
        """Find clusters of references that might indicate valid base addresses"""
        if not references:
            return []
        
        # Extract target addresses
        targets = [ref['to'] for ref in references]
        targets.sort()
        
        # Find clusters
        clusters = []
        current_cluster = [targets[0]]
        cluster_threshold = 0x10000  # 64KB
        
        for target in targets[1:]:
            if target - current_cluster[-1] <= cluster_threshold:
                current_cluster.append(target)
            else:
                if len(current_cluster) >= 3:
                    clusters.append(current_cluster)
                current_cluster = [target]
        
        if len(current_cluster) >= 3:
            clusters.append(current_cluster)
        
        return clusters

class AdvancedBaseAddressDetector:
    """Advanced base address detector with multiple analysis methods"""
    
    def __init__(self, program):
        self.program = program
        self.arch_analyzer = ArchitectureAnalyzer(program)
        self.pointer_extractor = PointerExtractor(program, self.arch_analyzer)
        self.string_analyzer = StringAnalyzer(program)
        self.statistical_analyzer = StatisticalAnalyzer(program, self.arch_analyzer)
        self.firmware_analyzer = FirmwareAnalyzer(program)
        self.entropy_analyzer = EntropyAnalyzer(program)
        self.xref_analyzer = CrossReferenceAnalyzer(program)
        
        # Initialize architecture-specific analyzers
        arch = self.arch_analyzer.get_architecture()
        if arch == 'MIPS':
            self.arch_specific = MIPSAnalyzer(program)
        elif arch == 'ARM':
            self.arch_specific = ARMAnalyzer(program)
        elif arch == 'x86':
            self.arch_specific = x86Analyzer(program)
        else:
            self.arch_specific = None
    
    def detect_base_address_advanced(self, config=None):
        """Advanced base address detection with multiple methods"""
        if config is None:
            config = self._get_advanced_config()
        
        print("Starting advanced base address detection...")
        print("Architecture: {}".format(self.arch_analyzer.get_architecture()))
        
        results = {}
        
        # Method 1: Traditional pointer analysis
        print("\n[Method 1] Traditional pointer analysis...")
        traditional_results = self._traditional_analysis(config)
        results['traditional'] = traditional_results
        
        # Method 2: Architecture-specific analysis
        print("\n[Method 2] Architecture-specific analysis...")
        arch_results = self._architecture_specific_analysis(config)
        results['architecture_specific'] = arch_results
        
        # Method 3: Cross-reference analysis
        print("\n[Method 3] Cross-reference analysis...")
        xref_results = self._cross_reference_analysis(config)
        results['cross_reference'] = xref_results
        
        # Method 4: Entropy-based analysis
        print("\n[Method 4] Entropy-based analysis...")
        entropy_results = self._entropy_analysis(config)
        results['entropy'] = entropy_results
        
        # Method 5: Pattern-based analysis
        print("\n[Method 5] Pattern-based analysis...")
        pattern_results = self._pattern_analysis(config)
        results['pattern'] = pattern_results
        
        # Combine and rank results
        print("\n[Final] Combining and ranking results...")
        final_candidates = self._combine_results(results, config)
        
        return final_candidates
    
    def _traditional_analysis(self, config):
        """Traditional pointer and string analysis"""
        # Use the original detection method
        detector = BaseAddressDetector(self.program)
        return detector.detect_base_address(config)
    
    def _architecture_specific_analysis(self, config):
        """Architecture-specific pattern analysis"""
        candidates = []
        
        if not self.arch_specific:
            return candidates
        
        arch = self.arch_analyzer.get_architecture()
        file_size = self._get_file_size()
        
        if arch == 'MIPS':
            # MIPS-specific analysis
            lui_ori_pairs = self.arch_specific.find_lui_ori_pairs()
            lui_addiu_pairs = self.arch_specific.find_lui_addiu_pairs()
            
            all_addresses = ([pair['address'] for pair in lui_ori_pairs] + 
                           [pair['address'] for pair in lui_addiu_pairs])
            
            print("Found {} MIPS address patterns".format(len(all_addresses)))
            
        elif arch == 'ARM':
            # ARM-specific analysis
            literal_pools = self.arch_specific.find_literal_pools()
            prologues = self.arch_specific.find_function_prologues()
            branch_targets = self.arch_specific.analyze_branch_targets()
            
            all_addresses = ([pool['pool_address'] for pool in literal_pools] +
                           [prologue['address'] for prologue in prologues] +
                           [target['target_address'] for target in branch_targets])
            
            print("Found {} ARM patterns".format(len(all_addresses)))
            
        elif arch == 'x86':
            # x86-specific analysis
            direct_addresses = self.arch_specific.find_direct_addresses()
            call_targets = self.arch_specific.find_call_targets()
            
            all_addresses = ([addr['address'] for addr in direct_addresses] +
                           [target['target_address'] for target in call_targets])
            
            print("Found {} x86 patterns".format(len(all_addresses)))
        
        # Analyze the addresses to find base address candidates
        if all_addresses:
            clusters = self.statistical_analyzer.cluster_addresses(all_addresses, file_size)
            search_ranges = self.statistical_analyzer.calculate_search_ranges(clusters, file_size)
            
            alignment = self.arch_analyzer.get_alignment()
            for range_start, range_end in search_ranges:
                for base_addr in range(range_start, range_end + 1, alignment):
                    if config.get('min_base_address', 0) <= base_addr <= config.get('max_base_address', 0xFFFFFFFF):
                        # Score this candidate
                        valid_count = sum(1 for addr in all_addresses 
                                        if 0 <= addr - base_addr < file_size)
                        confidence = float(valid_count) / len(all_addresses) if all_addresses else 0
                        
                        if confidence > 0.1:
                            result = BaseAddressResult(
                                base_addr, confidence, 
                                {'architecture_pattern': confidence},
                                0, arch
                            )
                            candidates.append(result)
        
        return sorted(candidates, key=lambda x: x.confidence, reverse=True)[:5]
    
    def _cross_reference_analysis(self, config):
        """Analyze cross-references for base address detection"""
        candidates = []
        
        patterns = self.xref_analyzer.analyze_reference_patterns()
        
        # Analyze function call patterns
        call_clusters = self.xref_analyzer.find_reference_clusters(patterns['function_calls'])
        data_clusters = self.xref_analyzer.find_reference_clusters(patterns['data_references'])
        
        print("Found {} call clusters, {} data clusters".format(
            len(call_clusters), len(data_clusters)))
        
        file_size = self._get_file_size()
        alignment = self.arch_analyzer.get_alignment()
        
        # Analyze clusters to find base address candidates
        all_clusters = call_clusters + data_clusters
        for cluster in all_clusters:
            min_addr = min(cluster)
            max_addr = max(cluster)
            
            # Calculate potential base address range
            range_start = (min_addr - file_size) & ~(alignment - 1)
            range_end = max_addr & ~(alignment - 1)
            
            for base_addr in range(range_start, range_end + 1, alignment * 16):
                if config.get('min_base_address', 0) <= base_addr <= config.get('max_base_address', 0xFFFFFFFF):
                    valid_refs = sum(1 for addr in cluster 
                                   if 0 <= addr - base_addr < file_size)
                    confidence = float(valid_refs) / len(cluster)
                    
                    if confidence > 0.3:
                        result = BaseAddressResult(
                            base_addr, confidence,
                            {'cross_reference': confidence},
                            0, self.arch_analyzer.get_architecture()
                        )
                        candidates.append(result)
        
        return sorted(candidates, key=lambda x: x.confidence, reverse=True)[:5]
    
    def _entropy_analysis(self, config):
        """Use entropy analysis to find code regions and infer base addresses"""
        candidates = []
        
        # Find low-entropy regions (likely code)
        low_entropy_regions = self.entropy_analyzer.find_low_entropy_regions()
        
        print("Found {} low-entropy regions".format(len(low_entropy_regions)))
        
        # Analyze these regions for patterns
        for region in low_entropy_regions:
            if region['entropy'] < 5.0:  # Very structured data/code
                # This could be a code region, analyze for base address hints
                start_addr = region['start_address']
                
                # Look for common base address patterns in this region
                # This is a simplified heuristic
                if start_addr > 0x10000:  # Reasonable base address
                    confidence = (6.0 - region['entropy']) / 6.0  # Higher confidence for lower entropy
                    
                    result = BaseAddressResult(
                        start_addr & ~0xFFF,  # Align to 4KB boundary
                        confidence * 0.5,  # Lower confidence for entropy-based detection
                        {'entropy_analysis': confidence},
                        0, self.arch_analyzer.get_architecture()
                    )
                    candidates.append(result)
        
        return sorted(candidates, key=lambda x: x.confidence, reverse=True)[:3]
    
    def _pattern_analysis(self, config):
        """Analyze various patterns for base address detection"""
        candidates = []
        
        # Look for common firmware patterns
        patterns_found = []
        
        # Pattern 1: Repeated address patterns
        instruction_iter = self.program.getListing().getInstructions(True)
        address_frequency = {}
        
        for instruction in instruction_iter:
            for i in range(instruction.getNumOperands()):
                operands = instruction.getOpObjects(i)
                for operand in operands:
                    if hasattr(operand, 'getOffset'):
                        addr = operand.getOffset()
                        if addr > 0x1000:  # Filter out small values
                            address_frequency[addr] = address_frequency.get(addr, 0) + 1
        
        # Find frequently referenced addresses
        frequent_addresses = [addr for addr, count in address_frequency.items() if count >= 3]
        
        print("Found {} frequently referenced addresses".format(len(frequent_addresses)))
        
        if frequent_addresses:
            file_size = self._get_file_size()
            alignment = self.arch_analyzer.get_alignment()
            
            # Use frequent addresses to infer base addresses
            clusters = self.statistical_analyzer.cluster_addresses(frequent_addresses, file_size)
            search_ranges = self.statistical_analyzer.calculate_search_ranges(clusters, file_size)
            
            for range_start, range_end in search_ranges:
                for base_addr in range(range_start, range_end + 1, alignment * 4):
                    if config.get('min_base_address', 0) <= base_addr <= config.get('max_base_address', 0xFFFFFFFF):
                        valid_count = sum(1 for addr in frequent_addresses 
                                        if 0 <= addr - base_addr < file_size)
                        confidence = float(valid_count) / len(frequent_addresses)
                        
                        if confidence > 0.2:
                            result = BaseAddressResult(
                                base_addr, confidence,
                                {'pattern_analysis': confidence},
                                0, self.arch_analyzer.get_architecture()
                            )
                            candidates.append(result)
        
        return sorted(candidates, key=lambda x: x.confidence, reverse=True)[:3]
    
    def _combine_results(self, results, config):
        """Combine results from all methods and rank them"""
        all_candidates = []
        
        # Collect all candidates
        for method, candidates in results.items():
            for candidate in candidates:
                candidate.notes.append("Detected by: {}".format(method))
                all_candidates.append(candidate)
        
        # Group candidates by address (with some tolerance)
        grouped_candidates = {}
        tolerance = 0x1000  # 4KB tolerance
        
        for candidate in all_candidates:
            # Find if this address is close to an existing group
            found_group = False
            for group_addr in grouped_candidates.keys():
                if abs(candidate.address - group_addr) <= tolerance:
                    grouped_candidates[group_addr].append(candidate)
                    found_group = True
                    break
            
            if not found_group:
                grouped_candidates[candidate.address] = [candidate]
        
        # Create combined candidates
        final_candidates = []
        for group_addr, group_candidates in grouped_candidates.items():
            # Combine scores from multiple methods
            combined_confidence = 0
            combined_scores = {}
            combined_notes = []
            
            for candidate in group_candidates:
                combined_confidence += candidate.confidence
                for method, score in candidate.method_scores.items():
                    combined_scores[method] = max(combined_scores.get(method, 0), score)
                combined_notes.extend(candidate.notes)
            
            # Average confidence but boost for multiple detections
            avg_confidence = combined_confidence / len(group_candidates)
            boost_factor = min(1.5, 1.0 + (len(group_candidates) - 1) * 0.2)
            final_confidence = min(avg_confidence * boost_factor, 1.0)
            
            final_result = BaseAddressResult(
                group_addr, final_confidence, combined_scores,
                0, self.arch_analyzer.get_architecture()
            )
            final_result.notes = list(set(combined_notes))  # Remove duplicates
            final_candidates.append(final_result)
        
        # Sort by confidence
        final_candidates.sort(key=lambda x: x.confidence, reverse=True)
        
        return final_candidates[:config.get('max_results', 10)]
    
    def _get_advanced_config(self):
        """Get advanced configuration"""
        return {
            'min_string_length': 4,
            'min_base_address': 0x00000000,
            'max_base_address': 0xFFFFFFFF,
            'min_confidence': 0.05,  # Lower threshold for advanced analysis
            'max_results': 15
        }
    
    def _get_file_size(self):
        """Get the size of the loaded file"""
        total_size = 0
        for block in self.program.getMemory().getBlocks():
            total_size += block.getSize()
        return total_size

def main_advanced():
    """Main function for advanced detection"""
    if currentProgram is None:
        print("No program loaded. Please load a firmware file first.")
        return
    
    print("=" * 70)
    print("Advanced Base Address Detection Script")
    print("Author: mobilemutex")
    print("=" * 70)
    
    # Create advanced detector
    detector = AdvancedBaseAddressDetector(currentProgram)
    
    # Run advanced detection
    results = detector.detect_base_address_advanced()
    
    # Display results
    print("\n" + "=" * 50)
    print("ADVANCED DETECTION RESULTS")
    print("=" * 50)
    
    if not results:
        print("No candidate base addresses found.")
        print("\nPossible reasons:")
        print("- Position-independent code")
        print("- Encrypted/compressed firmware")
        print("- Unusual architecture or format")
        print("- Need manual analysis")
        return
    
    for i, result in enumerate(results):
        print("\nCandidate #{}: 0x{:08X}".format(i + 1, result.address))
        print("  Confidence: {:.2%}".format(result.confidence))
        print("  Architecture: {}".format(result.architecture))
        
        if result.method_scores:
            print("  Detection Methods:")
            for method, score in result.method_scores.items():
                print("    {}: {:.2%}".format(method.replace('_', ' ').title(), score))
        
        if result.notes:
            print("  Notes:")
            for note in result.notes:
                print("    - {}".format(note))
    
    # Provide detailed recommendations
    if results:
        best_result = results[0]
        print("\n" + "=" * 50)
        print("RECOMMENDATION")
        print("=" * 50)
        print("Primary candidate: 0x{:08X}".format(best_result.address))
        print("Confidence level: {:.2%}".format(best_result.confidence))
        
        if best_result.confidence >= 0.7:
            print("Status: HIGH confidence - Recommended for use")
        elif best_result.confidence >= 0.4:
            print("Status: MEDIUM confidence - Verify with manual analysis")
        else:
            print("Status: LOW confidence - Manual analysis required")
        
        print("\nNext steps:")
        print("1. Set base address to 0x{:08X} in Ghidra".format(best_result.address))
        print("2. Re-analyze the program")
        print("3. Verify cross-references and function detection")
        print("4. Check for reasonable disassembly output")
        
        if len(results) > 1:
            print("\nAlternative candidates to try if primary fails:")
            for i, alt_result in enumerate(results[1:4], 2):
                print("  {}: 0x{:08X} (confidence: {:.2%})".format(
                    i, alt_result.address, alt_result.confidence))

# Allow running either version
if __name__ == "__main__":
    # Ask user which version to run
    print("Select detection mode:")
    print("1. Standard detection")
    print("2. Advanced detection (recommended)")
    
    try:
        choice = raw_input("Enter choice (1 or 2): ").strip()
        if choice == "1":
            main()
        else:
            main_advanced()
    except:
        # Default to advanced if input fails
        main_advanced()

