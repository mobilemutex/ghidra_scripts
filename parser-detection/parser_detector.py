# Ghidra Parser Function Detection Script
# @author mobilemutex
# @category Analysis
# @keybinding
# @menupath
# @toolbar

# Ghidra imports
from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.address import Address
from ghidra.program.model.mem import MemoryAccessException
from ghidra.app.services import DataTypeManagerService
from ghidra.util.task import TaskMonitor
from ghidra.program.model.data import DataType
from ghidra.program.model.listing import Instruction
from ghidra.program.model.scalar import Scalar
from ghidra.app.plugin.core.navigation import NavigationUtils
from ghidra.program.util import ProgramLocation
from ghidra.framework.plugintool import PluginTool

import re
import time

class ParserDetector:
    """
    Main class for detecting parser functions in Ghidra
    """
    
    def __init__(self):
        """Initialize the parser detector with configurable patterns"""
        
        # Configuration: String signatures commonly found in parsing functions
        self.PARSING_KEYWORDS = [
            "parse", "decode", "unpack", "deserialize", "unmarshal",
            "read", "header", "magic", "version", "format",
            "packet", "message", "buffer", "stream", "data",
            "protocol", "frame", "chunk", "block", "segment",
            "extract", "process", "handle", "interpret", "analyze",
            "validate", "verify", "check", "scan", "load"
        ]
        
        # Configuration: Common I/O and memory manipulation functions
        self.IO_FUNCTIONS = [
            "memcpy", "memmove", "memset", "memcmp", "memchr",
            "read", "recv", "recvfrom", "fread", "fgets",
            "sscanf", "sprintf", "snprintf", "strncpy", "strcpy",
            "strlen", "strcmp", "strncmp", "strstr", "strchr",
            "ntohl", "ntohs", "htonl", "htons",  # Network byte order
            "malloc", "calloc", "realloc", "free"
        ]
        
        # Configuration: Field access patterns (common structure offsets)
        self.COMMON_OFFSETS = [
            0x0, 0x4, 0x8, 0xc, 0x10, 0x14, 0x18, 0x1c,
            0x20, 0x24, 0x28, 0x2c, 0x30, 0x34, 0x38, 0x3c
        ]
        
        # Results storage
        self.detected_functions = []
        self.analysis_stats = {
            'total_functions': 0,
            'string_matches': 0,
            'loop_patterns': 0,
            'field_access_patterns': 0,
            'io_function_calls': 0,
            'total_detected': 0
        }
        
        # Get current program and other Ghidra objects
        self.currentProgram = getCurrentProgram()
        self.functionManager = self.currentProgram.getFunctionManager()
        self.listing = self.currentProgram.getListing()
        self.memory = self.currentProgram.getMemory()
        self.symbolTable = self.currentProgram.getSymbolTable()
        self.bookmarkManager = self.currentProgram.getBookmarkManager()
        
        print("[*] Parser Detector initialized")
        print("[*] Target Program: {}".format(self.currentProgram.getName()))
        print("[*] Architecture: {}".format(self.currentProgram.getLanguage().getProcessor()))
        
    def log_message(self, message, level="INFO"):
        """Log messages with timestamp"""
        timestamp = time.strftime("%H:%M:%S")
        print("[{}] [{}] {}".format(timestamp, level, message))
        
    def is_parsing_related_string(self, string_data):
        """
        Check if a string contains parsing-related keywords
        
        Args:
            string_data (str): The string to analyze
            
        Returns:
            bool: True if the string appears to be parsing-related
        """
        if not string_data:
            return False
            
        string_lower = string_data.lower()
        
        # Check for direct keyword matches
        for keyword in self.PARSING_KEYWORDS:
            if keyword in string_lower:
                return True
                
        # Check for common file format signatures
        format_patterns = [
            r'^\x7fELF',  # ELF magic
            r'^PK\x03\x04',  # ZIP magic
            r'^\x89PNG',  # PNG magic
            r'^GIF8[79]a',  # GIF magic
            r'^\xff\xd8\xff',  # JPEG magic
            r'^%PDF',  # PDF magic
            r'^\x50\x4b',  # ZIP/Office formats
        ]
        
        for pattern in format_patterns:
            if re.search(pattern, string_data):
                return True
                
        return False
        
    def find_string_references(self):
        """
        Find functions that reference parsing-related strings
        
        Returns:
            dict: Dictionary mapping function addresses to related strings
        """
        self.log_message("Analyzing string references...")
        string_refs = {}
        
        # Iterate through all defined data in the program
        data_iterator = self.listing.getDefinedData(True)
        
        for data in data_iterator:
            if data.hasStringValue():
                try:
                    string_value = data.getValue()
                    if isinstance(string_value, str) and self.is_parsing_related_string(string_value):
                        # Find references to this string
                        refs = getReferencesTo(data.getAddress())
                        
                        for ref in refs:
                            ref_addr = ref.getFromAddress()
                            func = self.functionManager.getFunctionContaining(ref_addr)
                            
                            if func:
                                func_addr = func.getEntryPoint()
                                if func_addr not in string_refs:
                                    string_refs[func_addr] = []
                                string_refs[func_addr].append({
                                    'string': string_value,
                                    'string_addr': data.getAddress(),
                                    'ref_addr': ref_addr
                                })
                                
                except Exception as e:
                    # Skip problematic strings
                    continue
                    
        self.analysis_stats['string_matches'] = len(string_refs)
        self.log_message("Found {} functions with parsing-related string references".format(len(string_refs)))
        
        return string_refs
        
    def analyze_function_for_loops(self, function):
        """
        Analyze a function for loop constructs that might indicate parsing
        
        Args:
            function: Ghidra Function object
            
        Returns:
            dict: Analysis results including loop indicators
        """
        loop_indicators = {
            'has_loops': False,
            'loop_count': 0,
            'increment_operations': 0,
            'comparison_operations': 0,
            'memory_access_in_loops': 0
        }
        
        try:
            # Get the function's address set
            body = function.getBody()
            
            # Analyze instructions in the function
            instruction_iter = self.listing.getInstructions(body, True)
            
            prev_instructions = []
            for instruction in instruction_iter:
                mnemonic = instruction.getMnemonicString().upper()
                
                # Look for jump instructions that might indicate loops
                if mnemonic in ['JMP', 'JNZ', 'JZ', 'JE', 'JNE', 'JL', 'JLE', 'JG', 'JGE']:
                    # Check if this is a backward jump (potential loop)
                    target_addr = None
                    if instruction.getNumOperands() > 0:
                        operand = instruction.getOpObjects(0)
                        if operand and len(operand) > 0:
                            if hasattr(operand[0], 'getOffset'):
                                target_offset = operand[0].getOffset()
                                current_offset = instruction.getAddress().getOffset()
                                
                                # Backward jump indicates potential loop
                                if target_offset < current_offset:
                                    loop_indicators['has_loops'] = True
                                    loop_indicators['loop_count'] += 1
                
                # Look for increment/decrement operations
                if mnemonic in ['INC', 'DEC', 'ADD', 'SUB']:
                    loop_indicators['increment_operations'] += 1
                
                # Look for comparison operations
                if mnemonic in ['CMP', 'TEST']:
                    loop_indicators['comparison_operations'] += 1
                
                # Look for memory access patterns
                if mnemonic in ['MOV', 'MOVZX', 'MOVSX', 'LEA']:
                    # Check if accessing memory with offset patterns
                    for i in range(instruction.getNumOperands()):
                        operand_objs = instruction.getOpObjects(i)
                        if operand_objs:
                            for obj in operand_objs:
                                if hasattr(obj, 'getOffset'):
                                    offset = obj.getOffset()
                                    if offset in self.COMMON_OFFSETS:
                                        loop_indicators['memory_access_in_loops'] += 1
                
                prev_instructions.append(instruction)
                # Keep only last 10 instructions for context
                if len(prev_instructions) > 10:
                    prev_instructions.pop(0)
                    
        except Exception as e:
            self.log_message("Error analyzing function {}: {}".format(function.getName(), str(e)), "ERROR")
            
        return loop_indicators
        
    def analyze_field_access_patterns(self, function):
        """
        Analyze a function for sequential field access patterns
        
        Args:
            function: Ghidra Function object
            
        Returns:
            dict: Field access analysis results
        """
        field_access = {
            'sequential_access': False,
            'offset_count': 0,
            'unique_offsets': set(),
            'base_registers': set()
        }
        
        try:
            body = function.getBody()
            instruction_iter = self.listing.getInstructions(body, True)
            
            offset_sequence = []
            
            for instruction in instruction_iter:
                mnemonic = instruction.getMnemonicString().upper()
                
                # Look for memory access instructions
                if mnemonic in ['MOV', 'MOVZX', 'MOVSX', 'LEA', 'CMP']:
                    for i in range(instruction.getNumOperands()):
                        operand_repr = instruction.getDefaultOperandRepresentation(i)
                        
                        # Look for patterns like [reg+offset] or [reg+0xNN]
                        offset_match = re.search(r'\[([^+]+)\+0x([0-9a-fA-F]+)\]', operand_repr)
                        if not offset_match:
                            offset_match = re.search(r'\[([^+]+)\+([0-9]+)\]', operand_repr)
                            
                        if offset_match:
                            base_reg = offset_match.group(1)
                            offset_str = offset_match.group(2)
                            
                            try:
                                if offset_str.startswith('0x'):
                                    offset = int(offset_str, 16)
                                else:
                                    offset = int(offset_str)
                                    
                                field_access['base_registers'].add(base_reg)
                                field_access['unique_offsets'].add(offset)
                                offset_sequence.append(offset)
                                
                            except ValueError:
                                continue
            
            field_access['offset_count'] = len(offset_sequence)
            
            # Check for sequential access pattern
            if len(offset_sequence) >= 3:
                # Sort offsets and check if they form a sequence
                sorted_offsets = sorted(set(offset_sequence))
                sequential_count = 0
                
                for i in range(len(sorted_offsets) - 1):
                    diff = sorted_offsets[i + 1] - sorted_offsets[i]
                    if diff in [1, 2, 4, 8]:  # Common field sizes
                        sequential_count += 1
                        
                if sequential_count >= 2:
                    field_access['sequential_access'] = True
                    
        except Exception as e:
            self.log_message("Error analyzing field access for {}: {}".format(function.getName(), str(e)), "ERROR")
            
        return field_access
        
    def find_io_function_calls(self, function):
        """
        Find calls to common I/O and memory manipulation functions
        
        Args:
            function: Ghidra Function object
            
        Returns:
            list: List of I/O function calls found
        """
        io_calls = []
        
        try:
            body = function.getBody()
            instruction_iter = self.listing.getInstructions(body, True)
            
            for instruction in instruction_iter:
                mnemonic = instruction.getMnemonicString().upper()
                
                # Look for call instructions
                if mnemonic in ['CALL', 'CALLQ']:
                    # Get the call target
                    if instruction.getNumOperands() > 0:
                        operand_repr = instruction.getDefaultOperandRepresentation(0)
                        
                        # Check if the call target matches any I/O function
                        for io_func in self.IO_FUNCTIONS:
                            if io_func.lower() in operand_repr.lower():
                                io_calls.append({
                                    'function': io_func,
                                    'address': instruction.getAddress(),
                                    'full_call': operand_repr
                                })
                                break
                                
        except Exception as e:
            self.log_message("Error finding I/O calls in {}: {}".format(function.getName(), str(e)), "ERROR")
            
        return io_calls


    def calculate_parser_score(self, function, string_refs, loop_analysis, field_analysis, io_calls):
        """
        Calculate a confidence score for a function being a parser
        
        Args:
            function: Ghidra Function object
            string_refs: List of parsing-related string references
            loop_analysis: Loop analysis results
            field_analysis: Field access analysis results
            io_calls: List of I/O function calls
            
        Returns:
            dict: Scoring results with confidence level
        """
        score = 0
        reasons = []
        
        # String reference scoring (0-30 points)
        if string_refs:
            string_score = min(len(string_refs) * 10, 30)
            score += string_score
            reasons.append("References {} parsing-related strings (+{} pts)".format(len(string_refs), string_score))
        
        # Loop analysis scoring (0-25 points)
        if loop_analysis['has_loops']:
            loop_score = 10
            if loop_analysis['loop_count'] > 1:
                loop_score += 5
            if loop_analysis['increment_operations'] > 3:
                loop_score += 5
            if loop_analysis['memory_access_in_loops'] > 2:
                loop_score += 5
            
            score += loop_score
            reasons.append("Contains loop constructs (+{} pts)".format(loop_score))
        
        # Field access scoring (0-20 points)
        if field_analysis['sequential_access']:
            field_score = 15
            score += field_score
            reasons.append("Sequential field access pattern (+{} pts)".format(field_score))
        elif field_analysis['offset_count'] > 3:
            field_score = 10
            score += field_score
            reasons.append("Multiple field accesses (+{} pts)".format(field_score))
        
        # I/O function call scoring (0-25 points)
        if io_calls:
            io_score = min(len(io_calls) * 8, 25)
            score += io_score
            reasons.append("Calls {} I/O functions (+{} pts)".format(len(io_calls), io_score))
        
        # Function name bonus (0-10 points)
        func_name = function.getName().lower()
        name_keywords = ['parse', 'read', 'decode', 'unpack', 'process', 'handle']
        for keyword in name_keywords:
            if keyword in func_name:
                score += 10
                reasons.append("Function name contains '{}' (+10 pts)".format(keyword))
                break
        
        # Function size consideration (bonus for medium-sized functions)
        func_size = function.getBody().getNumAddresses()
        if 50 <= func_size <= 500:  # Sweet spot for parser functions
            score += 5
            reasons.append("Appropriate function size (+5 pts)")
        
        # Determine confidence level
        if score >= 70:
            confidence = "HIGH"
        elif score >= 40:
            confidence = "MEDIUM"
        elif score >= 20:
            confidence = "LOW"
        else:
            confidence = "VERY_LOW"
        
        return {
            'score': score,
            'confidence': confidence,
            'reasons': reasons,
            'function_size': func_size
        }
    
    def analyze_all_functions(self):
        """
        Main analysis function that processes all functions in the program
        """
        self.log_message("Starting comprehensive function analysis...")
        
        # Get all functions in the program
        functions = self.functionManager.getFunctions(True)
        self.analysis_stats['total_functions'] = self.functionManager.getFunctionCount()
        
        # Find string references first (this is expensive, so do it once)
        string_refs_map = self.find_string_references()
        
        function_count = 0
        for function in functions:
            function_count += 1
            
            # Skip very small functions (likely not parsers)
            if function.getBody().getNumAddresses() < 10:
                continue
            
            # Skip thunk functions
            if function.isThunk():
                continue
                
            func_addr = function.getEntryPoint()
            func_name = function.getName()
            
            # Progress indicator
            if function_count % 100 == 0:
                self.log_message("Analyzed {} functions...".format(function_count))
            
            try:
                # Get string references for this function
                string_refs = string_refs_map.get(func_addr, [])
                
                # Perform various analyses
                loop_analysis = self.analyze_function_for_loops(function)
                field_analysis = self.analyze_field_access_patterns(function)
                io_calls = self.find_io_function_calls(function)
                
                # Calculate parser score
                scoring_result = self.calculate_parser_score(
                    function, string_refs, loop_analysis, field_analysis, io_calls
                )
                
                # Only keep functions with meaningful scores
                if scoring_result['score'] >= 15:  # Minimum threshold
                    detection_result = {
                        'function': function,
                        'address': func_addr,
                        'name': func_name,
                        'score': scoring_result['score'],
                        'confidence': scoring_result['confidence'],
                        'reasons': scoring_result['reasons'],
                        'string_refs': string_refs,
                        'loop_analysis': loop_analysis,
                        'field_analysis': field_analysis,
                        'io_calls': io_calls,
                        'function_size': scoring_result['function_size']
                    }
                    
                    self.detected_functions.append(detection_result)
                    
            except Exception as e:
                self.log_message("Error analyzing function {}: {}".format(func_name, str(e)), "ERROR")
                continue
        
        # Sort results by score (highest first)
        self.detected_functions.sort(key=lambda x: x['score'], reverse=True)
        self.analysis_stats['total_detected'] = len(self.detected_functions)
        
        self.log_message("Analysis complete. Found {} potential parser functions".format(len(self.detected_functions)))
    
    def annotate_functions(self):
        """
        Add comments and bookmarks to detected parser functions
        """
        self.log_message("Annotating detected parser functions...")
        
        for result in self.detected_functions:
            function = result['function']
            address = result['address']
            confidence = result['confidence']
            score = result['score']
            
            try:
                # Create comment text
                comment_lines = [
                    "=== POTENTIAL PARSER FUNCTION ===",
                    "Confidence: {} (Score: {})".format(confidence, score),
                    "Detection reasons:"
                ]
                
                for reason in result['reasons']:
                    comment_lines.append("  - {}".format(reason))
                
                if result['string_refs']:
                    comment_lines.append("String references:")
                    for ref in result['string_refs'][:3]:  # Limit to first 3
                        comment_lines.append("  - \"{}\"".format(ref['string'][:50]))
                
                if result['io_calls']:
                    comment_lines.append("I/O function calls:")
                    for call in result['io_calls'][:3]:  # Limit to first 3
                        comment_lines.append("  - {}".format(call['function']))
                
                comment_text = "\n".join(comment_lines)
                
                # Set the comment at the function entry point
                self.listing.setComment(address, CodeUnit.PLATE_COMMENT, comment_text)
                
                # Create bookmark
                bookmark_category = "Parser Functions"
                bookmark_comment = "{} confidence parser (score: {})".format(confidence, score)
                
                self.bookmarkManager.setBookmark(
                    address,
                    bookmark_category,
                    bookmark_category,
                    bookmark_comment
                )
                
            except Exception as e:
                self.log_message("Error annotating function {}: {}".format(function.getName(), str(e)), "ERROR")
        
        self.log_message("Annotation complete")
    
    def print_results(self):
        """
        Print detailed results to the Ghidra console
        """
        print("\n" + "="*80)
        print("PARSER FUNCTION DETECTION RESULTS")
        print("="*80)
        print("Program: {}".format(self.currentProgram.getName()))
        print("Analysis Date: {}".format(time.strftime("%Y-%m-%d %H:%M:%S")))
        print()
        
        # Print statistics
        print("ANALYSIS STATISTICS:")
        print("-" * 40)
        print("Total functions analyzed: {}".format(self.analysis_stats['total_functions']))
        print("Functions with string matches: {}".format(self.analysis_stats['string_matches']))
        print("Total potential parsers found: {}".format(self.analysis_stats['total_detected']))
        print()
        
        if not self.detected_functions:
            print("No potential parser functions detected.")
            return
        
        # Group results by confidence level
        confidence_groups = {}
        for result in self.detected_functions:
            conf = result['confidence']
            if conf not in confidence_groups:
                confidence_groups[conf] = []
            confidence_groups[conf].append(result)
        
        # Print results by confidence level
        for confidence in ['HIGH', 'MEDIUM', 'LOW', 'VERY_LOW']:
            if confidence not in confidence_groups:
                continue
                
            functions = confidence_groups[confidence]
            print("{} CONFIDENCE FUNCTIONS ({} found):".format(confidence, len(functions)))
            print("-" * 60)
            
            for i, result in enumerate(functions, 1):
                print("{}. {} (Score: {})".format(i, result['name'], result['score']))
                print("   Address: {}".format(result['address']))
                print("   Size: {} instructions".format(result['function_size']))
                
                # Print top reasons
                print("   Key indicators:")
                for reason in result['reasons'][:3]:  # Top 3 reasons
                    print("     - {}".format(reason))
                
                # Print some string references if available
                if result['string_refs']:
                    print("   Related strings:")
                    for ref in result['string_refs'][:2]:  # First 2 strings
                        string_preview = ref['string'][:40]
                        if len(ref['string']) > 40:
                            string_preview += "..."
                        print("     - \"{}\"".format(string_preview))
                
                print()
            
            print()
        
        print("="*80)
        print("Analysis complete. Functions have been bookmarked and annotated.")
        print("Use the Bookmark Manager to navigate to detected functions.")
        print("="*80)
    
    def run_analysis(self):
        """
        Main entry point for the analysis
        """
        start_time = time.time()
        
        try:
            self.log_message("Starting parser function detection analysis...")
            
            # Run the main analysis
            self.analyze_all_functions()
            
            # Annotate the detected functions
            self.annotate_functions()
            
            # Print results
            self.print_results()
            
            elapsed_time = time.time() - start_time
            self.log_message("Analysis completed in {:.2f} seconds".format(elapsed_time))
            
        except Exception as e:
            self.log_message("Critical error during analysis: {}".format(str(e)), "ERROR")
            import traceback
            traceback.print_exc()

# Configuration class for easy customization
class ParserDetectorConfig:
    """
    Configuration class for customizing the parser detection
    """
    
    @staticmethod
    def get_custom_keywords():
        """
        Return custom parsing keywords
        Override this method to add domain-specific keywords
        """
        return [
            # Add your custom keywords here
            # Example: "custom_parse", "my_decode", "special_format"
        ]
    
    @staticmethod
    def get_custom_io_functions():
        """
        Return custom I/O function names
        Override this method to add domain-specific I/O functions
        """
        return [
            # Add your custom I/O functions here
            # Example: "custom_read", "my_recv", "special_copy"
        ]
    
    @staticmethod
    def get_minimum_score_threshold():
        """
        Return the minimum score threshold for detection
        Lower values will detect more functions but with more false positives
        """
        return 15  # Default threshold
    
    @staticmethod
    def get_confidence_thresholds():
        """
        Return confidence level thresholds
        """
        return {
            'HIGH': 70,
            'MEDIUM': 40,
            'LOW': 20
        }

def main():
    """
    Main function to run the parser detector
    """
    # Check if we're running in Ghidra
    try:
        current_program = getCurrentProgram()
        if current_program is None:
            print("Error: No program is currently loaded in Ghidra")
            return
    except:
        print("Error: This script must be run within Ghidra")
        return
    
    # Create and run the detector
    detector = ParserDetector()
    
    # Apply custom configuration if needed
    custom_keywords = ParserDetectorConfig.get_custom_keywords()
    if custom_keywords:
        detector.PARSING_KEYWORDS.extend(custom_keywords)
        print("[*] Added {} custom parsing keywords".format(len(custom_keywords)))
    
    custom_io_functions = ParserDetectorConfig.get_custom_io_functions()
    if custom_io_functions:
        detector.IO_FUNCTIONS.extend(custom_io_functions)
        print("[*] Added {} custom I/O functions".format(len(custom_io_functions)))
    
    # Run the analysis
    detector.run_analysis()

# Run the script
if __name__ == "__main__":
    main()



# Additional utility functions for enhanced analysis

class AdvancedPatternAnalyzer:
    """
    Advanced pattern analysis utilities for more sophisticated detection
    """
    
    def __init__(self, program):
        self.program = program
        self.listing = program.getListing()
        
    def detect_state_machine_patterns(self, function):
        """
        Detect state machine patterns common in protocol parsers
        
        Args:
            function: Ghidra Function object
            
        Returns:
            dict: State machine analysis results
        """
        state_machine_indicators = {
            'has_switch_statements': False,
            'switch_count': 0,
            'state_variables': 0,
            'transition_patterns': 0
        }
        
        try:
            body = function.getBody()
            instruction_iter = self.listing.getInstructions(body, True)
            
            # Look for jump table patterns (common in switch statements)
            jump_table_refs = 0
            comparison_chains = 0
            
            prev_instruction = None
            for instruction in instruction_iter:
                mnemonic = instruction.getMnemonicString().upper()
                
                # Detect jump tables
                if mnemonic in ['JMP'] and prev_instruction:
                    prev_mnemonic = prev_instruction.getMnemonicString().upper()
                    if prev_mnemonic in ['CMP', 'TEST']:
                        jump_table_refs += 1
                
                # Count comparison chains (multiple CMPs in sequence)
                if mnemonic == 'CMP':
                    comparison_chains += 1
                
                prev_instruction = instruction
            
            # Heuristics for state machine detection
            if jump_table_refs > 2:
                state_machine_indicators['has_switch_statements'] = True
                state_machine_indicators['switch_count'] = jump_table_refs
            
            if comparison_chains > 5:
                state_machine_indicators['transition_patterns'] = comparison_chains
                
        except Exception as e:
            pass
            
        return state_machine_indicators
    
    def analyze_buffer_bounds_checking(self, function):
        """
        Analyze function for buffer bounds checking patterns
        
        Args:
            function: Ghidra Function object
            
        Returns:
            dict: Bounds checking analysis results
        """
        bounds_check = {
            'has_bounds_checks': False,
            'length_comparisons': 0,
            'size_validations': 0,
            'overflow_protections': 0
        }
        
        try:
            body = function.getBody()
            instruction_iter = self.listing.getInstructions(body, True)
            
            for instruction in instruction_iter:
                mnemonic = instruction.getMnemonicString().upper()
                
                # Look for size/length comparisons
                if mnemonic == 'CMP':
                    # Check operands for size-related patterns
                    for i in range(instruction.getNumOperands()):
                        operand_repr = instruction.getDefaultOperandRepresentation(i)
                        
                        # Common size validation patterns
                        if any(pattern in operand_repr.lower() for pattern in 
                               ['size', 'length', 'len', 'count', 'max', 'limit']):
                            bounds_check['length_comparisons'] += 1
                
                # Look for conditional jumps after comparisons (bounds checking)
                elif mnemonic in ['JA', 'JAE', 'JB', 'JBE', 'JG', 'JGE', 'JL', 'JLE']:
                    bounds_check['size_validations'] += 1
            
            # Determine if function has meaningful bounds checking
            if (bounds_check['length_comparisons'] > 1 and 
                bounds_check['size_validations'] > 2):
                bounds_check['has_bounds_checks'] = True
                
        except Exception as e:
            pass
            
        return bounds_check
    
    def detect_endianness_handling(self, function):
        """
        Detect byte order conversion patterns
        
        Args:
            function: Ghidra Function object
            
        Returns:
            dict: Endianness handling analysis results
        """
        endian_patterns = {
            'has_byte_swapping': False,
            'network_conversions': 0,
            'manual_swapping': 0
        }
        
        try:
            body = function.getBody()
            instruction_iter = self.listing.getInstructions(body, True)
            
            for instruction in instruction_iter:
                mnemonic = instruction.getMnemonicString().upper()
                
                # Look for byte swapping instructions
                if mnemonic in ['BSWAP', 'XCHG']:
                    endian_patterns['manual_swapping'] += 1
                
                # Look for calls to network byte order functions
                elif mnemonic in ['CALL', 'CALLQ']:
                    if instruction.getNumOperands() > 0:
                        operand_repr = instruction.getDefaultOperandRepresentation(0)
                        network_funcs = ['ntohl', 'ntohs', 'htonl', 'htons']
                        
                        for func in network_funcs:
                            if func in operand_repr.lower():
                                endian_patterns['network_conversions'] += 1
                                break
            
            if (endian_patterns['network_conversions'] > 0 or 
                endian_patterns['manual_swapping'] > 0):
                endian_patterns['has_byte_swapping'] = True
                
        except Exception as e:
            pass
            
        return endian_patterns

class ReportGenerator:
    """
    Generate detailed analysis reports
    """
    
    def __init__(self, detector_results):
        self.results = detector_results
        
    def generate_csv_report(self, output_path):
        """
        Generate CSV report of detected functions
        
        Args:
            output_path (str): Path to save the CSV file
        """
        try:
            import csv
            
            with open(output_path, 'w', newline='') as csvfile:
                fieldnames = [
                    'Function Name', 'Address', 'Score', 'Confidence',
                    'Function Size', 'String References', 'Loop Patterns',
                    'Field Access', 'I/O Calls', 'Primary Reasons'
                ]
                
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for result in self.results:
                    writer.writerow({
                        'Function Name': result['name'],
                        'Address': str(result['address']),
                        'Score': result['score'],
                        'Confidence': result['confidence'],
                        'Function Size': result['function_size'],
                        'String References': len(result['string_refs']),
                        'Loop Patterns': 'Yes' if result['loop_analysis']['has_loops'] else 'No',
                        'Field Access': 'Yes' if result['field_analysis']['sequential_access'] else 'No',
                        'I/O Calls': len(result['io_calls']),
                        'Primary Reasons': '; '.join(result['reasons'][:3])
                    })
                    
            print("[*] CSV report saved to: {}".format(output_path))
            
        except Exception as e:
            print("[ERROR] Failed to generate CSV report: {}".format(str(e)))
    
    def generate_html_report(self, output_path):
        """
        Generate HTML report with interactive features
        
        Args:
            output_path (str): Path to save the HTML file
        """
        try:
            html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>Parser Function Detection Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .function-card { 
            border: 1px solid #ddd; 
            margin: 10px 0; 
            padding: 15px; 
            border-radius: 5px; 
        }
        .high-confidence { border-left: 5px solid #28a745; }
        .medium-confidence { border-left: 5px solid #ffc107; }
        .low-confidence { border-left: 5px solid #dc3545; }
        .score { font-weight: bold; font-size: 1.2em; }
        .reasons { margin-top: 10px; }
        .reason { margin: 5px 0; padding: 3px 8px; background-color: #e9ecef; border-radius: 3px; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Parser Function Detection Report</h1>
        <p><strong>Generated:</strong> {}</p>
        <p><strong>Total Functions Detected:</strong> {}</p>
    </div>
""".format(time.strftime("%Y-%m-%d %H:%M:%S"), len(self.results))
            
            # Group by confidence
            confidence_groups = {}
            for result in self.results:
                conf = result['confidence']
                if conf not in confidence_groups:
                    confidence_groups[conf] = []
                confidence_groups[conf].append(result)
            
            for confidence in ['HIGH', 'MEDIUM', 'LOW', 'VERY_LOW']:
                if confidence not in confidence_groups:
                    continue
                    
                functions = confidence_groups[confidence]
                html_content += """
    <h2>{} Confidence Functions ({})</h2>
""".format(confidence, len(functions))
                
                for result in functions:
                    confidence_class = confidence.lower().replace('_', '-') + '-confidence'
                    
                    html_content += """
    <div class="function-card {}">
        <h3>{}</h3>
        <p><strong>Address:</strong> {}</p>
        <p><strong>Score:</strong> <span class="score">{}</span></p>
        <p><strong>Function Size:</strong> {} instructions</p>
        <div class="reasons">
            <strong>Detection Reasons:</strong>
""".format(confidence_class, result['name'], result['address'], 
           result['score'], result['function_size'])
                    
                    for reason in result['reasons']:
                        html_content += '            <div class="reason">{}</div>\n'.format(reason)
                    
                    html_content += """        </div>
    </div>
"""
            
            html_content += """
</body>
</html>"""
            
            with open(output_path, 'w') as f:
                f.write(html_content)
                
            print("[*] HTML report saved to: {}".format(output_path))
            
        except Exception as e:
            print("[ERROR] Failed to generate HTML report: {}".format(str(e)))

# Enhanced main function with additional options
def run_enhanced_analysis():
    """
    Run enhanced analysis with additional pattern detection
    """
    try:
        current_program = getCurrentProgram()
        if current_program is None:
            print("Error: No program is currently loaded in Ghidra")
            return
    except:
        print("Error: This script must be run within Ghidra")
        return
    
    print("\n" + "="*60)
    print("ENHANCED PARSER FUNCTION DETECTOR")
    print("="*60)
    
    # Create detector with enhanced analysis
    detector = ParserDetector()
    advanced_analyzer = AdvancedPatternAnalyzer(current_program)
    
    # Run basic analysis
    detector.run_analysis()
    
    # Run enhanced analysis on detected functions
    print("\n[*] Running enhanced pattern analysis...")
    
    for result in detector.detected_functions:
        function = result['function']
        
        # Add advanced analysis results
        state_machine = advanced_analyzer.detect_state_machine_patterns(function)
        bounds_check = advanced_analyzer.analyze_buffer_bounds_checking(function)
        endian_handling = advanced_analyzer.detect_endianness_handling(function)
        
        # Update score based on advanced patterns
        bonus_score = 0
        if state_machine['has_switch_statements']:
            bonus_score += 10
            result['reasons'].append("Contains state machine patterns (+10 pts)")
        
        if bounds_check['has_bounds_checks']:
            bonus_score += 8
            result['reasons'].append("Has buffer bounds checking (+8 pts)")
        
        if endian_handling['has_byte_swapping']:
            bonus_score += 5
            result['reasons'].append("Handles byte order conversion (+5 pts)")
        
        result['score'] += bonus_score
        result['advanced_patterns'] = {
            'state_machine': state_machine,
            'bounds_check': bounds_check,
            'endian_handling': endian_handling
        }
    
    # Re-sort by updated scores
    detector.detected_functions.sort(key=lambda x: x['score'], reverse=True)
    
    # Generate reports
    report_gen = ReportGenerator(detector.detected_functions)
    
    # Ask user if they want to generate reports
    print("\n[*] Analysis complete!")
    print("[*] Would you like to generate additional reports? (Modify script to enable)")
    
    # Uncomment these lines to generate reports automatically:
    # report_gen.generate_csv_report("/tmp/parser_functions.csv")
    # report_gen.generate_html_report("/tmp/parser_functions.html")
    
    return detector.detected_functions

# Alternative entry points for different use cases
def quick_scan():
    """Quick scan with lower thresholds for broader detection"""
    detector = ParserDetector()
    # Lower the threshold for quicker, broader detection
    original_threshold = ParserDetectorConfig.get_minimum_score_threshold()
    ParserDetectorConfig.get_minimum_score_threshold = lambda: 10
    
    detector.run_analysis()
    return detector.detected_functions

def focused_scan(function_name_pattern):
    """
    Focused scan on functions matching a specific name pattern
    
    Args:
        function_name_pattern (str): Regex pattern to match function names
    """
    detector = ParserDetector()
    
    # Override the analyze_all_functions method to filter by name
    original_method = detector.analyze_all_functions
    
    def filtered_analysis():
        functions = detector.functionManager.getFunctions(True)
        pattern = re.compile(function_name_pattern, re.IGNORECASE)
        
        filtered_functions = [f for f in functions if pattern.search(f.getName())]
        print("[*] Analyzing {} functions matching pattern '{}'".format(
            len(filtered_functions), function_name_pattern))
        
        # Process only filtered functions
        for function in filtered_functions:
            # ... (same analysis logic as original method)
            pass
    
    detector.analyze_all_functions = filtered_analysis
    detector.run_analysis()
    return detector.detected_functions

