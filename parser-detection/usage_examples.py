#!/usr/bin/env python
"""
Usage Examples for Ghidra Parser Detection Script

This file contains practical examples of how to use and customize
the parser detection script for different scenarios.
"""

# Example 1: Basic usage with default settings
def example_basic_usage():
    """
    Basic usage example - run with default settings
    """
    from ghidra_parser_detector import main
    
    print("Running basic parser detection...")
    main()

# Example 2: Custom configuration for network protocol analysis
def example_network_protocol_analysis():
    """
    Example configuration for analyzing network protocol parsers
    """
    from ghidra_parser_detector import ParserDetector, ParserDetectorConfig
    
    # Custom configuration for network protocols
    class NetworkProtocolConfig(ParserDetectorConfig):
        @staticmethod
        def get_custom_keywords():
            return [
                "packet", "frame", "header", "payload", "checksum",
                "protocol", "tcp", "udp", "ip", "ethernet",
                "socket", "network", "recv", "send", "transmit",
                "serialize", "deserialize", "encode", "decode"
            ]
        
        @staticmethod
        def get_custom_io_functions():
            return [
                "recv", "recvfrom", "send", "sendto",
                "socket", "bind", "listen", "accept",
                "ntohl", "ntohs", "htonl", "htons"
            ]
        
        @staticmethod
        def get_minimum_score_threshold():
            return 20  # Slightly higher threshold for network analysis
    
    # Create detector with custom config
    detector = ParserDetector()
    
    # Apply custom configuration
    detector.PARSING_KEYWORDS.extend(NetworkProtocolConfig.get_custom_keywords())
    detector.IO_FUNCTIONS.extend(NetworkProtocolConfig.get_custom_io_functions())
    
    print("Running network protocol parser detection...")
    detector.run_analysis()

# Example 3: File format parser detection
def example_file_format_analysis():
    """
    Example configuration for analyzing file format parsers
    """
    from ghidra_parser_detector import ParserDetector
    
    # Custom keywords for file format analysis
    file_format_keywords = [
        "magic", "signature", "version", "header", "footer",
        "chunk", "block", "section", "entry", "record",
        "compress", "decompress", "inflate", "deflate",
        "zip", "tar", "rar", "pdf", "jpeg", "png", "gif",
        "elf", "pe", "mach", "format", "parser", "loader"
    ]
    
    file_format_functions = [
        "fopen", "fread", "fwrite", "fseek", "ftell",
        "mmap", "munmap", "lseek", "pread", "pwrite",
        "inflate", "deflate", "compress", "uncompress"
    ]
    
    detector = ParserDetector()
    detector.PARSING_KEYWORDS.extend(file_format_keywords)
    detector.IO_FUNCTIONS.extend(file_format_functions)
    
    print("Running file format parser detection...")
    detector.run_analysis()

# Example 4: Malware analysis configuration
def example_malware_analysis():
    """
    Example configuration for malware analysis
    """
    from ghidra_parser_detector import ParserDetector
    
    # Keywords common in malware command parsing
    malware_keywords = [
        "command", "cmd", "instruction", "opcode", "bot",
        "c2", "cnc", "beacon", "implant", "backdoor",
        "config", "configuration", "decrypt", "encrypt",
        "xor", "rc4", "aes", "base64", "hex", "obfuscate"
    ]
    
    # Functions commonly used in malware
    malware_functions = [
        "CreateProcess", "WriteProcessMemory", "VirtualAlloc",
        "GetProcAddress", "LoadLibrary", "RegOpenKey",
        "InternetOpen", "HttpSendRequest", "CryptDecrypt"
    ]
    
    detector = ParserDetector()
    detector.PARSING_KEYWORDS.extend(malware_keywords)
    detector.IO_FUNCTIONS.extend(malware_functions)
    
    # Lower threshold for malware analysis (more permissive)
    print("Running malware parser detection...")
    detector.run_analysis()

# Example 5: Quick scan for large binaries
def example_quick_scan():
    """
    Quick scan example for large binaries
    """
    from ghidra_parser_detector import quick_scan
    
    print("Running quick scan...")
    results = quick_scan()
    
    print("Quick scan found {} potential parsers".format(len(results)))
    
    # Print top 10 results
    for i, result in enumerate(results[:10], 1):
        print("{}. {} (Score: {})".format(
            i, result['name'], result['score']))

# Example 6: Focused analysis on specific functions
def example_focused_analysis():
    """
    Focused analysis on functions matching specific patterns
    """
    from ghidra_parser_detector import focused_scan
    
    # Analyze only functions with "parse" in the name
    print("Running focused analysis on 'parse' functions...")
    results = focused_scan(r".*parse.*")
    
    # Analyze functions that might be message handlers
    print("Running focused analysis on message handlers...")
    results = focused_scan(r".*(msg|message|handle|process).*")
    
    return results

# Example 7: Generate comprehensive reports
def example_generate_reports():
    """
    Example of generating detailed reports
    """
    from ghidra_parser_detector import ParserDetector, ReportGenerator
    import os
    
    # Run analysis
    detector = ParserDetector()
    detector.run_analysis()
    
    # Generate reports
    report_gen = ReportGenerator(detector.detected_functions)
    
    # Create output directory
    output_dir = "/tmp/parser_analysis"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Generate CSV report
    csv_path = os.path.join(output_dir, "parser_functions.csv")
    report_gen.generate_csv_report(csv_path)
    
    # Generate HTML report
    html_path = os.path.join(output_dir, "parser_functions.html")
    report_gen.generate_html_report(html_path)
    
    print("Reports generated in: {}".format(output_dir))

# Example 8: Custom scoring function
def example_custom_scoring():
    """
    Example of implementing custom scoring logic
    """
    from ghidra_parser_detector import ParserDetector
    
    class CustomScoringDetector(ParserDetector):
        def calculate_parser_score(self, function, string_refs, loop_analysis, field_analysis, io_calls):
            # Call parent scoring method
            base_result = super().calculate_parser_score(
                function, string_refs, loop_analysis, field_analysis, io_calls)
            
            score = base_result['score']
            reasons = base_result['reasons'][:]
            
            # Add custom scoring logic
            func_name = function.getName().lower()
            
            # Bonus for functions in specific namespaces
            if "::" in func_name:
                namespace = func_name.split("::")[0]
                if namespace in ["parser", "protocol", "format", "codec"]:
                    score += 15
                    reasons.append("Function in parsing namespace (+15 pts)")
            
            # Penalty for very common function names
            common_names = ["main", "init", "cleanup", "free", "alloc"]
            if any(name in func_name for name in common_names):
                score -= 10
                reasons.append("Common function name (-10 pts)")
            
            # Bonus for functions with parameter counts typical of parsers
            param_count = len(function.getParameters())
            if 2 <= param_count <= 5:  # Typical parser parameter count
                score += 5
                reasons.append("Appropriate parameter count (+5 pts)")
            
            # Update confidence based on new score
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
                'function_size': base_result['function_size']
            }
    
    # Use custom detector
    detector = CustomScoringDetector()
    detector.run_analysis()

# Example 9: Integration with other Ghidra scripts
def example_integration_workflow():
    """
    Example of integrating parser detection with other analysis workflows
    """
    from ghidra_parser_detector import ParserDetector
    
    # Step 1: Run parser detection
    detector = ParserDetector()
    detector.run_analysis()
    
    # Step 2: Process high-confidence results
    high_confidence_functions = [
        result for result in detector.detected_functions 
        if result['confidence'] == 'HIGH'
    ]
    
    print("Found {} high-confidence parser functions".format(
        len(high_confidence_functions)))
    
    # Step 3: Perform additional analysis on high-confidence functions
    for result in high_confidence_functions:
        function = result['function']
        address = result['address']
        
        print("Analyzing function: {} at {}".format(
            function.getName(), address))
        
        # Example: Analyze function parameters
        params = function.getParameters()
        print("  Parameters: {}".format(len(params)))
        
        # Example: Analyze function calls
        called_functions = []
        body = function.getBody()
        listing = getCurrentProgram().getListing()
        
        instruction_iter = listing.getInstructions(body, True)
        for instruction in instruction_iter:
            if instruction.getMnemonicString().upper() in ['CALL', 'CALLQ']:
                # Extract called function information
                pass
        
        # Example: Set additional bookmarks or comments
        # This could trigger other analysis scripts or workflows

# Example 10: Batch analysis of multiple programs
def example_batch_analysis():
    """
    Example framework for batch analysis of multiple programs
    Note: This would need to be adapted for actual batch processing
    """
    from ghidra_parser_detector import ParserDetector, ReportGenerator
    
    # This is a conceptual example - actual implementation would need
    # to handle program loading/unloading in Ghidra
    
    programs_to_analyze = [
        # List of program paths or identifiers
    ]
    
    all_results = {}
    
    for program_id in programs_to_analyze:
        print("Analyzing program: {}".format(program_id))
        
        # In actual implementation, you would load the program here
        # current_program = loadProgram(program_id)
        
        detector = ParserDetector()
        detector.run_analysis()
        
        all_results[program_id] = detector.detected_functions
        
        # Generate individual report
        report_gen = ReportGenerator(detector.detected_functions)
        report_path = "/tmp/analysis_{}.html".format(program_id)
        report_gen.generate_html_report(report_path)
    
    # Generate summary report across all programs
    print("Batch analysis complete. Analyzed {} programs".format(
        len(programs_to_analyze)))

# Configuration template for easy customization
class CustomAnalysisConfig:
    """
    Template for creating custom analysis configurations
    """
    
    # Domain-specific keywords
    CUSTOM_KEYWORDS = [
        # Add your domain-specific keywords here
        "your_keyword_1",
        "your_keyword_2",
        # ...
    ]
    
    # Domain-specific I/O functions
    CUSTOM_IO_FUNCTIONS = [
        # Add your domain-specific I/O functions here
        "your_io_function_1",
        "your_io_function_2",
        # ...
    ]
    
    # Scoring thresholds
    MIN_SCORE_THRESHOLD = 15
    HIGH_CONFIDENCE_THRESHOLD = 70
    MEDIUM_CONFIDENCE_THRESHOLD = 40
    LOW_CONFIDENCE_THRESHOLD = 20
    
    # Analysis options
    ENABLE_ADVANCED_PATTERNS = True
    ENABLE_STATE_MACHINE_DETECTION = True
    ENABLE_BOUNDS_CHECK_ANALYSIS = True
    ENABLE_ENDIAN_ANALYSIS = True
    
    @classmethod
    def apply_to_detector(cls, detector):
        """
        Apply this configuration to a detector instance
        """
        detector.PARSING_KEYWORDS.extend(cls.CUSTOM_KEYWORDS)
        detector.IO_FUNCTIONS.extend(cls.CUSTOM_IO_FUNCTIONS)
        
        # You can add more configuration application logic here
        return detector

# Main execution examples
if __name__ == "__main__":
    # Uncomment the example you want to run
    
    # example_basic_usage()
    # example_network_protocol_analysis()
    # example_file_format_analysis()
    # example_malware_analysis()
    # example_quick_scan()
    # example_focused_analysis()
    # example_generate_reports()
    # example_custom_scoring()
    # example_integration_workflow()
    
    print("Usage examples loaded. Uncomment the desired example to run.")

