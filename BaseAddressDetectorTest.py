# Base Address Detector Test and Validation Script
# Author: mobilemutex
# Description: Test framework for validating base address detection functionality

from ghidra.program.model.address import Address
from ghidra.program.model.listing import Instruction
from ghidra.program.model.mem import Memory, MemoryBlock
import time

class BaseAddressDetectorValidator:
    """Validation framework for base address detection"""
    
    def __init__(self, program):
        self.program = program
        self.memory = program.getMemory()
        self.listing = program.getListing()
        
    def validate_detection_results(self, results):
        """Validate the quality of detection results"""
        validation_report = {
            'total_candidates': len(results),
            'high_confidence': 0,
            'medium_confidence': 0,
            'low_confidence': 0,
            'validation_tests': []
        }
        
        for result in results:
            # Categorize by confidence
            if result.confidence >= 0.7:
                validation_report['high_confidence'] += 1
            elif result.confidence >= 0.4:
                validation_report['medium_confidence'] += 1
            else:
                validation_report['low_confidence'] += 1
            
            # Run validation tests
            test_results = self._run_validation_tests(result)
            validation_report['validation_tests'].append({
                'address': result.address,
                'confidence': result.confidence,
                'tests': test_results
            })
        
        return validation_report
    
    def _run_validation_tests(self, result):
        """Run specific validation tests on a candidate base address"""
        tests = {}
        
        # Test 1: Check if base address creates valid memory layout
        tests['memory_layout'] = self._test_memory_layout(result.address)
        
        # Test 2: Check instruction validity at entry points
        tests['instruction_validity'] = self._test_instruction_validity(result.address)
        
        # Test 3: Check cross-reference validity
        tests['cross_reference_validity'] = self._test_cross_references(result.address)
        
        # Test 4: Check string reference validity
        tests['string_reference_validity'] = self._test_string_references(result.address)
        
        # Test 5: Check for reasonable function boundaries
        tests['function_boundaries'] = self._test_function_boundaries(result.address)
        
        return tests
    
    def _test_memory_layout(self, base_address):
        """Test if the base address creates a reasonable memory layout"""
        try:
            file_size = self._get_file_size()
            
            # Check if the memory layout makes sense
            if base_address < 0x1000:
                return {'passed': False, 'reason': 'Base address too low'}
            
            if base_address > 0xFFFFFFFF - file_size:
                return {'passed': False, 'reason': 'Base address too high for file size'}
            
            # Check alignment
            if base_address % 4 != 0:
                return {'passed': False, 'reason': 'Base address not aligned'}
            
            return {'passed': True, 'reason': 'Memory layout appears valid'}
            
        except Exception as e:
            return {'passed': False, 'reason': 'Error testing memory layout: {}'.format(str(e))}
    
    def _test_instruction_validity(self, base_address):
        """Test if instructions at potential entry points are valid"""
        try:
            # Check first few instructions
            first_block = None
            for block in self.memory.getBlocks():
                if first_block is None or block.getStart().compareTo(first_block.getStart()) < 0:
                    first_block = block
            
            if first_block is None:
                return {'passed': False, 'reason': 'No memory blocks found'}
            
            # Check instructions at the beginning
            addr = first_block.getStart()
            valid_instructions = 0
            total_checked = 10
            
            for i in range(total_checked):
                try:
                    instruction = self.listing.getInstructionAt(addr.add(i * 4))
                    if instruction is not None:
                        valid_instructions += 1
                except:
                    pass
            
            validity_ratio = float(valid_instructions) / total_checked
            
            if validity_ratio >= 0.5:
                return {'passed': True, 'reason': 'Good instruction validity ({:.1%})'.format(validity_ratio)}
            else:
                return {'passed': False, 'reason': 'Poor instruction validity ({:.1%})'.format(validity_ratio)}
                
        except Exception as e:
            return {'passed': False, 'reason': 'Error testing instructions: {}'.format(str(e))}
    
    def _test_cross_references(self, base_address):
        """Test if cross-references make sense with this base address"""
        try:
            ref_manager = self.program.getReferenceManager()
            valid_refs = 0
            total_refs = 0
            file_size = self._get_file_size()
            
            # Check a sample of references
            all_refs = ref_manager.getReferenceIterator()
            for ref in all_refs:
                total_refs += 1
                if total_refs > 100:  # Limit sample size
                    break
                
                to_addr = ref.getToAddress().getOffset()
                file_offset = to_addr - base_address
                
                if 0 <= file_offset < file_size:
                    valid_refs += 1
            
            if total_refs == 0:
                return {'passed': True, 'reason': 'No references to validate'}
            
            validity_ratio = float(valid_refs) / total_refs
            
            if validity_ratio >= 0.3:
                return {'passed': True, 'reason': 'Good reference validity ({:.1%})'.format(validity_ratio)}
            else:
                return {'passed': False, 'reason': 'Poor reference validity ({:.1%})'.format(validity_ratio)}
                
        except Exception as e:
            return {'passed': False, 'reason': 'Error testing references: {}'.format(str(e))}
    
    def _test_string_references(self, base_address):
        """Test if string references are valid with this base address"""
        try:
            valid_string_refs = 0
            total_string_refs = 0
            file_size = self._get_file_size()
            
            # Get defined strings
            data_iter = self.listing.getDefinedData(True)
            for data in data_iter:
                if data.hasStringValue():
                    total_string_refs += 1
                    string_addr = data.getAddress().getOffset()
                    file_offset = string_addr - base_address
                    
                    if 0 <= file_offset < file_size:
                        valid_string_refs += 1
            
            if total_string_refs == 0:
                return {'passed': True, 'reason': 'No string references to validate'}
            
            validity_ratio = float(valid_string_refs) / total_string_refs
            
            if validity_ratio >= 0.5:
                return {'passed': True, 'reason': 'Good string validity ({:.1%})'.format(validity_ratio)}
            else:
                return {'passed': False, 'reason': 'Poor string validity ({:.1%})'.format(validity_ratio)}
                
        except Exception as e:
            return {'passed': False, 'reason': 'Error testing strings: {}'.format(str(e))}
    
    def _test_function_boundaries(self, base_address):
        """Test if function boundaries make sense"""
        try:
            function_manager = self.program.getFunctionManager()
            functions = function_manager.getFunctions(True)
            
            valid_functions = 0
            total_functions = 0
            file_size = self._get_file_size()
            
            for function in functions:
                total_functions += 1
                if total_functions > 50:  # Limit sample size
                    break
                
                func_addr = function.getEntryPoint().getOffset()
                file_offset = func_addr - base_address
                
                if 0 <= file_offset < file_size:
                    valid_functions += 1
            
            if total_functions == 0:
                return {'passed': True, 'reason': 'No functions to validate'}
            
            validity_ratio = float(valid_functions) / total_functions
            
            if validity_ratio >= 0.5:
                return {'passed': True, 'reason': 'Good function validity ({:.1%})'.format(validity_ratio)}
            else:
                return {'passed': False, 'reason': 'Poor function validity ({:.1%})'.format(validity_ratio)}
                
        except Exception as e:
            return {'passed': False, 'reason': 'Error testing functions: {}'.format(str(e))}
    
    def _get_file_size(self):
        """Get the size of the loaded file"""
        total_size = 0
        for block in self.memory.getBlocks():
            total_size += block.getSize()
        return total_size

class PerformanceTester:
    """Test performance of base address detection"""
    
    def __init__(self):
        pass
    
    def benchmark_detection(self, detector_class, program, iterations=3):
        """Benchmark the detection performance"""
        times = []
        
        for i in range(iterations):
            print("Running benchmark iteration {}...".format(i + 1))
            
            start_time = time.time()
            detector = detector_class(program)
            results = detector.detect_base_address()
            end_time = time.time()
            
            execution_time = end_time - start_time
            times.append(execution_time)
            
            print("Iteration {} completed in {:.2f} seconds".format(i + 1, execution_time))
        
        avg_time = sum(times) / len(times)
        min_time = min(times)
        max_time = max(times)
        
        return {
            'average_time': avg_time,
            'min_time': min_time,
            'max_time': max_time,
            'iterations': iterations
        }

def run_comprehensive_test():
    """Run comprehensive test of base address detection"""
    if currentProgram is None:
        print("No program loaded. Please load a firmware file first.")
        return
    
    print("=" * 60)
    print("Base Address Detector Comprehensive Test")
    print("Author: mobilemutex")
    print("=" * 60)
    
    # Test both standard and advanced detectors
    try:
        from BaseAddressDetector import BaseAddressDetector
        from BaseAddressDetectorAdvanced import AdvancedBaseAddressDetector
        
        print("\n[1] Testing Standard Detector...")
        print("-" * 40)
        
        # Test standard detector
        standard_detector = BaseAddressDetector(currentProgram)
        standard_results = standard_detector.detect_base_address()
        
        print("Standard detector found {} candidates".format(len(standard_results)))
        
        # Validate standard results
        validator = BaseAddressDetectorValidator(currentProgram)
        standard_validation = validator.validate_detection_results(standard_results)
        
        print("Validation results:")
        print("  High confidence: {}".format(standard_validation['high_confidence']))
        print("  Medium confidence: {}".format(standard_validation['medium_confidence']))
        print("  Low confidence: {}".format(standard_validation['low_confidence']))
        
        print("\n[2] Testing Advanced Detector...")
        print("-" * 40)
        
        # Test advanced detector
        advanced_detector = AdvancedBaseAddressDetector(currentProgram)
        advanced_results = advanced_detector.detect_base_address_advanced()
        
        print("Advanced detector found {} candidates".format(len(advanced_results)))
        
        # Validate advanced results
        advanced_validation = validator.validate_detection_results(advanced_results)
        
        print("Validation results:")
        print("  High confidence: {}".format(advanced_validation['high_confidence']))
        print("  Medium confidence: {}".format(advanced_validation['medium_confidence']))
        print("  Low confidence: {}".format(advanced_validation['low_confidence']))
        
        print("\n[3] Performance Benchmarking...")
        print("-" * 40)
        
        # Benchmark performance
        performance_tester = PerformanceTester()
        
        print("Benchmarking standard detector...")
        standard_perf = performance_tester.benchmark_detection(BaseAddressDetector, currentProgram, 2)
        
        print("Benchmarking advanced detector...")
        advanced_perf = performance_tester.benchmark_detection(AdvancedBaseAddressDetector, currentProgram, 2)
        
        print("\nPerformance Results:")
        print("Standard Detector:")
        print("  Average time: {:.2f} seconds".format(standard_perf['average_time']))
        print("  Min time: {:.2f} seconds".format(standard_perf['min_time']))
        print("  Max time: {:.2f} seconds".format(standard_perf['max_time']))
        
        print("Advanced Detector:")
        print("  Average time: {:.2f} seconds".format(advanced_perf['average_time']))
        print("  Min time: {:.2f} seconds".format(advanced_perf['min_time']))
        print("  Max time: {:.2f} seconds".format(advanced_perf['max_time']))
        
        print("\n[4] Detailed Validation Report...")
        print("-" * 40)
        
        # Show detailed validation for top candidates
        print("Standard Detector Top Candidate Validation:")
        if standard_results:
            top_standard = standard_validation['validation_tests'][0]
            print("  Address: 0x{:08X}".format(top_standard['address']))
            print("  Confidence: {:.2%}".format(top_standard['confidence']))
            for test_name, test_result in top_standard['tests'].items():
                status = "PASS" if test_result['passed'] else "FAIL"
                print("    {}: {} - {}".format(test_name, status, test_result['reason']))
        
        print("\nAdvanced Detector Top Candidate Validation:")
        if advanced_results:
            top_advanced = advanced_validation['validation_tests'][0]
            print("  Address: 0x{:08X}".format(top_advanced['address']))
            print("  Confidence: {:.2%}".format(top_advanced['confidence']))
            for test_name, test_result in top_advanced['tests'].items():
                status = "PASS" if test_result['passed'] else "FAIL"
                print("    {}: {} - {}".format(test_name, status, test_result['reason']))
        
        print("\n[5] Recommendations...")
        print("-" * 40)
        
        # Provide recommendations based on test results
        if advanced_results and advanced_results[0].confidence > 0.5:
            print("RECOMMENDATION: Use Advanced Detector")
            print("  Best candidate: 0x{:08X}".format(advanced_results[0].address))
            print("  Confidence: {:.2%}".format(advanced_results[0].confidence))
        elif standard_results and standard_results[0].confidence > 0.5:
            print("RECOMMENDATION: Use Standard Detector")
            print("  Best candidate: 0x{:08X}".format(standard_results[0].address))
            print("  Confidence: {:.2%}".format(standard_results[0].confidence))
        else:
            print("RECOMMENDATION: Manual Analysis Required")
            print("  Both detectors produced low-confidence results")
            print("  Consider:")
            print("    - Firmware may be encrypted/compressed")
            print("    - Position-independent code")
            print("    - Unusual architecture or format")
        
    except ImportError as e:
        print("Error importing detector modules: {}".format(str(e)))
        print("Make sure BaseAddressDetector.py and BaseAddressDetectorAdvanced.py are available")
    except Exception as e:
        print("Error during testing: {}".format(str(e)))

def quick_test():
    """Quick test of base address detection"""
    if currentProgram is None:
        print("No program loaded. Please load a firmware file first.")
        return
    
    print("Running quick base address detection test...")
    
    try:
        from BaseAddressDetector import BaseAddressDetector
        
        detector = BaseAddressDetector(currentProgram)
        results = detector.detect_base_address()
        
        print("Quick test completed.")
        print("Found {} candidates".format(len(results)))
        
        if results:
            best = results[0]
            print("Best candidate: 0x{:08X} (confidence: {:.2%})".format(
                best.address, best.confidence))
        
    except Exception as e:
        print("Error during quick test: {}".format(str(e)))

if __name__ == "__main__":
    # Ask user which test to run
    print("Select test mode:")
    print("1. Quick test")
    print("2. Comprehensive test")
    
    try:
        choice = raw_input("Enter choice (1 or 2): ").strip()
        if choice == "1":
            quick_test()
        else:
            run_comprehensive_test()
    except:
        # Default to quick test if input fails
        quick_test()

