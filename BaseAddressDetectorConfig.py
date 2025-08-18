# Base Address Detector Configuration
# Author: mobilemutex
# Description: Configuration options for base address detection

class DetectionConfig:
    """Configuration class for base address detection"""
    
    def __init__(self):
        # Basic detection parameters
        self.min_string_length = 4
        self.min_base_address = 0x00000000
        self.max_base_address = 0xFFFFFFFF
        self.min_confidence = 0.1
        self.max_results = 10
        
        # Architecture-specific settings
        self.force_architecture = None  # None for auto-detect, or 'MIPS', 'ARM', 'x86'
        self.custom_alignment = None    # None for auto-detect, or specific alignment
        
        # Method enablement
        self.enable_pointer_analysis = True
        self.enable_string_analysis = True
        self.enable_arch_specific = True
        self.enable_cross_reference = True
        self.enable_entropy_analysis = True
        self.enable_pattern_analysis = True
        
        # Advanced options
        self.entropy_threshold = 6.0
        self.cluster_threshold = 0x10000
        self.reference_sample_size = 100
        self.instruction_sample_size = 256
        
        # Scoring weights
        self.scoring_weights = {
            'pointer_alignment': 0.25,
            'string_reference': 0.20,
            'cross_reference': 0.20,
            'architecture_pattern': 0.15,
            'entropy_analysis': 0.10,
            'pattern_analysis': 0.10
        }
        
        # Firmware analysis settings
        self.detect_firmware_headers = True
        self.max_header_scan_size = 0x2000
        self.min_instruction_density = 0.5
        
        # Performance settings
        self.max_scan_size = 0x100000  # 1MB max scan
        self.enable_parallel_processing = False  # Not implemented yet
        
        # Output settings
        self.verbose_output = False
        self.export_results = False
        self.export_format = 'json'  # 'json' or 'csv'
        
    def get_mips_config(self):
        """Get configuration optimized for MIPS firmware"""
        config = DetectionConfig()
        config.force_architecture = 'MIPS'
        config.min_base_address = 0x80000000
        config.max_base_address = 0xBFFFFFFF
        config.custom_alignment = 4
        config.scoring_weights['architecture_pattern'] = 0.30
        return config
    
    def get_arm_config(self):
        """Get configuration optimized for ARM firmware"""
        config = DetectionConfig()
        config.force_architecture = 'ARM'
        config.min_base_address = 0x00000000
        config.max_base_address = 0xFFFFFFFF
        config.custom_alignment = 4
        config.scoring_weights['architecture_pattern'] = 0.25
        return config
    
    def get_x86_config(self):
        """Get configuration optimized for x86 firmware"""
        config = DetectionConfig()
        config.force_architecture = 'x86'
        config.min_base_address = 0x00400000
        config.max_base_address = 0x7FFFFFFF
        config.scoring_weights['cross_reference'] = 0.30
        return config
    
    def get_embedded_config(self):
        """Get configuration optimized for embedded firmware"""
        config = DetectionConfig()
        config.min_string_length = 3  # Shorter strings in embedded
        config.entropy_threshold = 5.5  # Lower threshold for embedded
        config.enable_entropy_analysis = True
        config.detect_firmware_headers = True
        return config
    
    def get_bootloader_config(self):
        """Get configuration optimized for bootloader analysis"""
        config = DetectionConfig()
        config.min_base_address = 0x00000000
        config.max_base_address = 0x00100000  # Bootloaders usually in low memory
        config.detect_firmware_headers = True
        config.max_header_scan_size = 0x1000
        config.scoring_weights['pattern_analysis'] = 0.20
        return config
    
    def get_high_confidence_config(self):
        """Get configuration for high-confidence detection only"""
        config = DetectionConfig()
        config.min_confidence = 0.5
        config.max_results = 5
        config.reference_sample_size = 200  # More thorough analysis
        return config
    
    def get_fast_config(self):
        """Get configuration for fast detection"""
        config = DetectionConfig()
        config.enable_entropy_analysis = False
        config.enable_pattern_analysis = False
        config.reference_sample_size = 50
        config.instruction_sample_size = 128
        config.max_scan_size = 0x10000
        return config
    
    def to_dict(self):
        """Convert configuration to dictionary"""
        return {
            'basic': {
                'min_string_length': self.min_string_length,
                'min_base_address': self.min_base_address,
                'max_base_address': self.max_base_address,
                'min_confidence': self.min_confidence,
                'max_results': self.max_results
            },
            'architecture': {
                'force_architecture': self.force_architecture,
                'custom_alignment': self.custom_alignment
            },
            'methods': {
                'enable_pointer_analysis': self.enable_pointer_analysis,
                'enable_string_analysis': self.enable_string_analysis,
                'enable_arch_specific': self.enable_arch_specific,
                'enable_cross_reference': self.enable_cross_reference,
                'enable_entropy_analysis': self.enable_entropy_analysis,
                'enable_pattern_analysis': self.enable_pattern_analysis
            },
            'advanced': {
                'entropy_threshold': self.entropy_threshold,
                'cluster_threshold': self.cluster_threshold,
                'reference_sample_size': self.reference_sample_size,
                'instruction_sample_size': self.instruction_sample_size
            },
            'scoring_weights': self.scoring_weights,
            'firmware': {
                'detect_firmware_headers': self.detect_firmware_headers,
                'max_header_scan_size': self.max_header_scan_size,
                'min_instruction_density': self.min_instruction_density
            },
            'performance': {
                'max_scan_size': self.max_scan_size,
                'enable_parallel_processing': self.enable_parallel_processing
            },
            'output': {
                'verbose_output': self.verbose_output,
                'export_results': self.export_results,
                'export_format': self.export_format
            }
        }
    
    def from_dict(self, config_dict):
        """Load configuration from dictionary"""
        if 'basic' in config_dict:
            basic = config_dict['basic']
            self.min_string_length = basic.get('min_string_length', self.min_string_length)
            self.min_base_address = basic.get('min_base_address', self.min_base_address)
            self.max_base_address = basic.get('max_base_address', self.max_base_address)
            self.min_confidence = basic.get('min_confidence', self.min_confidence)
            self.max_results = basic.get('max_results', self.max_results)
        
        if 'architecture' in config_dict:
            arch = config_dict['architecture']
            self.force_architecture = arch.get('force_architecture', self.force_architecture)
            self.custom_alignment = arch.get('custom_alignment', self.custom_alignment)
        
        if 'methods' in config_dict:
            methods = config_dict['methods']
            self.enable_pointer_analysis = methods.get('enable_pointer_analysis', self.enable_pointer_analysis)
            self.enable_string_analysis = methods.get('enable_string_analysis', self.enable_string_analysis)
            self.enable_arch_specific = methods.get('enable_arch_specific', self.enable_arch_specific)
            self.enable_cross_reference = methods.get('enable_cross_reference', self.enable_cross_reference)
            self.enable_entropy_analysis = methods.get('enable_entropy_analysis', self.enable_entropy_analysis)
            self.enable_pattern_analysis = methods.get('enable_pattern_analysis', self.enable_pattern_analysis)
        
        if 'scoring_weights' in config_dict:
            self.scoring_weights.update(config_dict['scoring_weights'])
        
        # Load other sections similarly...

# Predefined configurations
PRESET_CONFIGS = {
    'default': DetectionConfig(),
    'mips': DetectionConfig().get_mips_config(),
    'arm': DetectionConfig().get_arm_config(),
    'x86': DetectionConfig().get_x86_config(),
    'embedded': DetectionConfig().get_embedded_config(),
    'bootloader': DetectionConfig().get_bootloader_config(),
    'high_confidence': DetectionConfig().get_high_confidence_config(),
    'fast': DetectionConfig().get_fast_config()
}

def get_config(preset_name='default'):
    """Get a predefined configuration"""
    return PRESET_CONFIGS.get(preset_name, DetectionConfig())

def list_presets():
    """List available configuration presets"""
    return list(PRESET_CONFIGS.keys())

# Example usage functions
def run_with_config(detector_class, program, config_name='default'):
    """Run detector with a specific configuration"""
    config = get_config(config_name)
    detector = detector_class(program)
    
    # Convert config to the format expected by the detector
    config_dict = {
        'min_string_length': config.min_string_length,
        'min_base_address': config.min_base_address,
        'max_base_address': config.max_base_address,
        'min_confidence': config.min_confidence,
        'max_results': config.max_results
    }
    
    return detector.detect_base_address(config_dict)

def interactive_config():
    """Interactive configuration builder"""
    print("Base Address Detector Configuration Builder")
    print("=" * 50)
    
    config = DetectionConfig()
    
    # Basic settings
    print("\n1. Basic Settings:")
    try:
        min_str_len = raw_input("Minimum string length [{}]: ".format(config.min_string_length))
        if min_str_len.strip():
            config.min_string_length = int(min_str_len)
        
        min_base = raw_input("Minimum base address (hex) [0x{:08X}]: ".format(config.min_base_address))
        if min_base.strip():
            config.min_base_address = int(min_base, 16)
        
        max_base = raw_input("Maximum base address (hex) [0x{:08X}]: ".format(config.max_base_address))
        if max_base.strip():
            config.max_base_address = int(max_base, 16)
        
        min_conf = raw_input("Minimum confidence [{}]: ".format(config.min_confidence))
        if min_conf.strip():
            config.min_confidence = float(min_conf)
        
        max_results = raw_input("Maximum results [{}]: ".format(config.max_results))
        if max_results.strip():
            config.max_results = int(max_results)
    except:
        print("Using default values for invalid inputs")
    
    # Architecture settings
    print("\n2. Architecture Settings:")
    print("Available architectures: MIPS, ARM, x86, auto")
    try:
        arch = raw_input("Force architecture [auto]: ").strip().upper()
        if arch in ['MIPS', 'ARM', 'X86']:
            config.force_architecture = arch
    except:
        pass
    
    # Method enablement
    print("\n3. Detection Methods:")
    methods = [
        ('enable_pointer_analysis', 'Pointer analysis'),
        ('enable_string_analysis', 'String analysis'),
        ('enable_arch_specific', 'Architecture-specific analysis'),
        ('enable_cross_reference', 'Cross-reference analysis'),
        ('enable_entropy_analysis', 'Entropy analysis'),
        ('enable_pattern_analysis', 'Pattern analysis')
    ]
    
    for attr, desc in methods:
        try:
            current = getattr(config, attr)
            response = raw_input("{} [{}]: ".format(desc, 'Y' if current else 'N')).strip().upper()
            if response in ['Y', 'N']:
                setattr(config, attr, response == 'Y')
        except:
            pass
    
    print("\nConfiguration completed!")
    return config

if __name__ == "__main__":
    print("Base Address Detector Configuration")
    print("Available presets:", ', '.join(list_presets()))
    
    # Example of using different configurations
    print("\nExample configurations:")
    for preset_name in list_presets():
        config = get_config(preset_name)
        print("  {}: min_base=0x{:08X}, max_base=0x{:08X}".format(
            preset_name, config.min_base_address, config.max_base_address))

