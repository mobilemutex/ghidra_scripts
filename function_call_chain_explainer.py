# LLMReverseHelper.py - A Ghidra script for LLM-assisted reverse engineering
# @author mobilemutex
# @category Analysis
# @keybinding
# @menupath
# @toolbar

from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SourceType
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from java.awt import BorderLayout, GridLayout, FlowLayout
from javax.swing import JPanel, JLabel, JTextField, JButton, JScrollPane, JTextArea
from javax.swing.border import TitledBorder
import json
import urllib2
import traceback
import re

# Global variables
PLUGIN_NAME = "LLM Reverse Helper"
DEFAULT_SERVER_URL = "http://localhost"
DEFAULT_PORT = "8000"
DEFAULT_MODEL = "llama3.1:8b"
DEFAULT_MAX_TOKENS = 1024
CONFIG_PATH = "LLMReverseHelper.json"

class LLMReverseHelper:
    def __init__(self):
        self.flat_api = FlatProgramAPI(currentProgram)
        self.program = currentProgram
        self.function_manager = self.program.getFunctionManager()
        self.monitor = TaskMonitor.DUMMY
        self.decompiler = self.setup_decompiler()
        self.load_config()
        
    def setup_decompiler(self):
        """Set up the decompiler interface"""
        decompiler = DecompInterface()
        decompiler.openProgram(self.program)
        return decompiler
        
    def load_config(self):
        """Load configuration from file or use defaults"""
        try:
            config_file = open(CONFIG_PATH, "r")
            config = json.load(config_file)
            config_file.close()
            
            self.server_url = config.get("server_url", DEFAULT_SERVER_URL)
            self.port = config.get("port", DEFAULT_PORT)
            self.model = config.get("model", DEFAULT_MODEL)
            self.max_tokens = config.get("max_tokens", DEFAULT_MAX_TOKENS)
        except:
            # If config file doesn't exist or is invalid, use defaults
            self.server_url = DEFAULT_SERVER_URL
            self.port = DEFAULT_PORT
            self.model = DEFAULT_MODEL
            self.max_tokens = DEFAULT_MAX_TOKENS
            
    def save_config(self):
        """Save configuration to file"""
        config = {
            "server_url": self.server_url,
            "port": self.port,
            "model": self.model,
            "max_tokens": self.max_tokens
        }
        
        try:
            config_file = open(CONFIG_PATH, "w")
            json.dump(config, config_file)
            config_file.close()
            print(f"[+] Configuration saved to {CONFIG_PATH}")
        except:
            print(f"[-] Failed to save configuration to {CONFIG_PATH}")
            
    def query_llm(self, prompt, system_message="You are a reverse engineering assistant that specializes in analyzing decompiled code."):
        """Query the LLM using the OpenAI API format"""
        try:
            url = f"{self.server_url}:{self.port}/v1/chat/completions"
            
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": self.max_tokens,
                "temperature": 0.7
            }
            
            req = urllib2.Request(url)
            req.add_header('Content-Type', 'application/json')
            
            response = urllib2.urlopen(req, json.dumps(payload))
            result = json.loads(response.read())
            
            return result["choices"][0]["message"]["content"]
        except Exception as e:
            print(f"[-] Error querying LLM: {str(e)}")
            traceback.print_exc()
            return None
            
    def get_function_source(self, function):
        """Get the decompiled source of a function"""
        result = self.decompiler.decompileFunction(function, 60, self.monitor)
        if result and result.getDecompiledFunction() and result.getDecompiledFunction().getC():
            return result.getDecompiledFunction().getC()
        return None
        
    def is_default_name(self, function):
        """Check if a function has a default name (FUN_address format)"""
        name = function.getName()
        return name.startswith("FUN_")
        
    def build_call_graph(self, start_function):
        """Build a call graph from the starting function"""
        visited = set()
        call_graph = {}
        
        def visit_function(function):
            if function in visited:
                return
                
            visited.add(function)
            
            # Get all functions called by this function
            called_functions = set()
            for reference in function.getCalledFunctions(self.monitor):
                if self.is_default_name(reference):
                    called_functions.add(reference)
                    
            # Store called functions and recurse
            call_graph[function] = list(called_functions)
            for called_function in called_functions:
                visit_function(called_function)
                
        visit_function(start_function)
        return call_graph
        
    def get_leaf_functions(self, call_graph):
        """Get all leaf functions from the call graph"""
        leaf_functions = []
        
        for function, called_functions in call_graph.items():
            if len(called_functions) == 0:
                leaf_functions.append(function)
                
        return leaf_functions
        
    def process_call_graph(self, call_graph, start_function):
        """Process the call graph in order - leaf functions first"""
        # Create a topological ordering
        processed_functions = set()
        ordered_functions = []
        
        def process_function(function):
            if function in processed_functions:
                return
                
            # Process all called functions first
            for called_function in call_graph.get(function, []):
                process_function(called_function)
                
            processed_functions.add(function)
            ordered_functions.append(function)
            
        # Start processing from leaf functions
        leaf_functions = self.get_leaf_functions(call_graph)
        for function in leaf_functions:
            process_function(function)
            
        # Make sure our starting function is last
        if start_function in ordered_functions:
            ordered_functions.remove(start_function)
        ordered_functions.append(start_function)
        
        return ordered_functions
        
    def explain_function(self, function):
        """Get an explanation for a function from the LLM"""
        # Get decompiled code
        source = self.get_function_source(function)
        if not source:
            return None, None
            
        prompt = f"""Please analyze this decompiled function:

        '''
        {source}
        '''

        
        1. Explain the purpose of this function in 2-3 sentences.
        2. Suggest a descriptive name for this function that clearly identifies its purpose.
        
        Format your response as:
        EXPLANATION: Your 2-3 sentence explanation
        NAME: suggested_function_name
        """
        
        response = self.query_llm(prompt)
        if not response:
            return None, None
            
        # Parse the response
        explanation_match = re.search(r"EXPLANATION:\s*(.*?)(?:\n|$)", response, re.DOTALL)
        name_match = re.search(r"NAME:\s*(.*?)(?:\n|$)", response)
        
        explanation = explanation_match.group(1).strip() if explanation_match else None
        suggested_name = name_match.group(1).strip() if name_match else None
        
        # Clean up the suggested name to make it valid
        if suggested_name:
            # Remove non-alphanumeric characters except underscores
            suggested_name = re.sub(r'[^\w]', '_', suggested_name)
            # Ensure it starts with a letter
            if not suggested_name[0].isalpha():
                suggested_name = "func_" + suggested_name
                
        return explanation, suggested_name
        
    def add_plate_comment(self, function, comment):
        """Add a plate comment to a function"""
        self.flat_api.setPlateComment(function.getEntryPoint(), comment)
        
    def rename_function(self, function, new_name):
        """Rename a function with the suggested name"""
        try:
            function.setName(new_name, SourceType.USER_DEFINED)
            print(f"[+] Renamed function at {function.getEntryPoint()} to {new_name}")
            return True
        except Exception as e:
            print(f"[-] Failed to rename function: {str(e)}")
            return False
            
    def rename_variables_in_function(self, function):
        """Rename variables in a function with meaningful names"""
        source = self.get_function_source(function)
        if not source:
            return False
            
        prompt = f"""Please analyze the variables in this decompiled function and suggest meaningful names:

        '''
        {source}
        '''
        
        
        For each variable, suggest a descriptive name that indicates its purpose.
        Format your response as:
        VARIABLE: original_variable_name
        SUGGESTED_NAME: new_descriptive_name
        REASON: Brief reason for the name choice
        
        Repeat for each variable.
        """
        
        response = self.query_llm(prompt)
        if not response:
            return False
            
        # Parse variable renaming suggestions
        variable_patterns = re.finditer(r"VARIABLE:\s*(.*?)\nSUGGESTED_NAME:\s*(.*?)(?:\nREASON:|$)", response, re.DOTALL)
        
        renamed_count = 0
        for match in variable_patterns:
            original_name = match.group(1).strip()
            suggested_name = match.group(2).strip()
            
            # Clean up suggested name
            suggested_name = re.sub(r'[^\w]', '_', suggested_name)
            if not suggested_name[0].isalpha():
                suggested_name = "var_" + suggested_name
                
            # Find the variable in the function's namespace
            variable = None
            for var in function.getAllVariables():
                if var.getName() == original_name:
                    variable = var
                    break
                    
            if variable:
                try:
                    variable.setName(suggested_name, SourceType.USER_DEFINED)
                    print(f"[+] Renamed variable {original_name} to {suggested_name}")
                    renamed_count += 1
                except:
                    print(f"[-] Failed to rename variable {original_name}")
                    
        print(f"[+] Processed {renamed_count} variable renames for function {function.getName()}")
        return renamed_count > 0
        
    def generate_ascii_call_tree(self, call_graph, start_function):
        """Generate an ASCII representation of the call tree"""
        tree_lines = []
        
        def print_tree(function, depth=0, prefix=""):
            # Add this function to the tree
            tree_lines.append(f"{prefix}{function.getName()} @ {function.getEntryPoint()}")
            
            # Process children
            children = call_graph.get(function, [])
            for i, child in enumerate(children):
                if i == len(children) - 1:  # Last child
                    print_tree(child, depth + 1, prefix + "└── ")
                else:
                    print_tree(child, depth + 1, prefix + "├── ")
                    
        print_tree(start_function)
        return "\n".join(tree_lines)
        
    def process_function_chain(self, start_function):
        """Process the entire function call chain"""
        print(f"[+] Analyzing function: {start_function.getName()} @ {start_function.getEntryPoint()}")
        
        # Build call graph
        call_graph = self.build_call_graph(start_function)
        print(f"[+] Built call graph with {len(call_graph)} functions")
        
        # Process functions in the right order (leaf functions first)
        ordered_functions = self.process_call_graph(call_graph, start_function)
        print(f"[+] Processing {len(ordered_functions)} functions in topological order")
        
        # Process each function
        processed_count = 0
        for function in ordered_functions:
            if self.is_default_name(function) or function == start_function:
                print(f"[+] Processing function {function.getName()} @ {function.getEntryPoint()}")
                
                explanation, suggested_name = self.explain_function(function)
                
                if explanation:
                    self.add_plate_comment(function, explanation)
                    print(f"[+] Added explanation comment to {function.getName()}")
                    
                if suggested_name and self.is_default_name(function):
                    self.rename_function(function, suggested_name)
                    
                processed_count += 1
                
        # Generate and display the call tree
        call_tree = self.generate_ascii_call_tree(call_graph, start_function)
        print("\nCall Tree:")
        print(call_tree)
        
        print(f"\n[+] Processed {processed_count} functions")
        return True
        
    def analyze_binary_protections(self):
        """Analyze binary protections and security features"""
        prompt = "Analyze the following binary for security protections and features. Look for signs of ASLR, stack canaries, PIE, and other security mechanisms."
        
        # Add binary format information
        prompt += f"\nBinary format: {self.program.getExecutableFormat()}"
        
        # Add information about segments and sections
        prompt += "\nSections/Segments information:"
        memory_blocks = self.program.getMemory().getBlocks()
        for block in memory_blocks:
            prompt += f"\n- {block.getName()}: Start={block.getStart()}, End={block.getEnd()}, Permissions={block.getPermissions()}"
        
        result = self.query_llm(prompt)
        print("\n=== Binary Protection Analysis ===")
        print(result)
        
    def identify_algorithms(self, function):
        """Identify common algorithms in the function"""
        source = self.get_function_source(function)
        if not source:
            return
            
        prompt = f"""Analyze this decompiled function and identify if it implements any common algorithms (e.g., cryptographic algorithms, sorting algorithms,etc.):

        '''
        {source}
        '''
        
        
        If you identify a known algorithm, explain:
        1. What algorithm it is
        2. How confident you are in the identification
        3. Key characteristics that indicate this algorithm
        """
        
        result = self.query_llm(prompt)
        print("\n=== Algorithm Identification ===")
        print(result)
        
    def show_config_dialog(self):
        """Display a configuration dialog"""
        panel = JPanel(BorderLayout())
        
        # Server connection panel
        server_panel = JPanel(GridLayout(4, 2, 5, 5))
        server_panel.setBorder(TitledBorder("LLM Server Configuration"))
        
        server_panel.add(JLabel("Server URL:"))
        url_field = JTextField(self.server_url, 30)
        server_panel.add(url_field)
        
        server_panel.add(JLabel("Port:"))
        port_field = JTextField(self.port, 10)
        server_panel.add(port_field)
        
        server_panel.add(JLabel("Model:"))
        model_field = JTextField(self.model, 30)
        server_panel.add(model_field)
        
        server_panel.add(JLabel("Max Tokens:"))
        max_tokens_field = JTextField(str(self.max_tokens), 10)
        server_panel.add(max_tokens_field)
        
        panel.add(server_panel, BorderLayout.NORTH)
        
        # Test connection panel
        test_panel = JPanel(FlowLayout(FlowLayout.CENTER))
        test_button = JButton("Test Connection")
        
        class TestActionListener(java.awt.event.ActionListener):
            def __init__(self, helper):
                self.helper = helper
            def actionPerformed(self, event):
                self.helper.test_connection()
                
        test_button.addActionListener(TestActionListener(self))
        test_panel.add(test_button)
        
        panel.add(test_panel, BorderLayout.CENTER)
        
        # Save panel
        save_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        save_button = JButton("Save Configuration")
        
        class SaveActionListener(java.awt.event.ActionListener):
            def __init__(self, helper, url_field, port_field, model_field, max_tokens_field):
                self.helper = helper
                self.url_field = url_field
                self.port_field = port_field
                self.model_field = model_field
                self.max_tokens_field = max_tokens_field
            def actionPerformed(self, event):
                self.helper.save_config_from_dialog(
                    self.url_field.getText(),
                    self.port_field.getText(),
                    self.model_field.getText(),
                    int(self.max_tokens_field.getText())
                )
                
        save_button.addActionListener(SaveActionListener(self, url_field, port_field, model_field, max_tokens_field))
        save_panel.add(save_button)
        
        panel.add(save_panel, BorderLayout.SOUTH)
        
        if askDialog(panel, "LLM Reverse Helper Configuration"):
            # Dialog was confirmed, save configuration
            self.save_config_from_dialog(
                url_field.getText(),
                port_field.getText(),
                model_field.getText(),
                int(max_tokens_field.getText())
            )
            
    def save_config_from_dialog(self, url, port, model, max_tokens):
        """Save configuration from dialog"""
        self.server_url = url
        self.port = port
        self.model = model
        self.max_tokens = max_tokens
        self.save_config()
        
    def test_connection(self):
        """Test the connection to the LLM server"""
        try:
            result = self.query_llm("Hello, are you working?", "Respond briefly with 'Yes, I am working.'")
            if result:
                print("[+] Connection successful")
                popup(f"Connection successful!\nResponse: {result}")
            else:
                print("[-] Connection failed")
                popup("Connection failed. Check logs for details.")
        except Exception as e:
            print(f"[-] Connection test error: {str(e)}")
            traceback.print_exc()
            popup(f"Connection error: {str(e)}")
            
    def show_main_menu(self):
        """Show the main menu for the LLM Reverse Helper"""
        # Get current function
        current_function = getFunctionContaining(currentAddress)
        if not current_function:
            popup("Please position cursor inside a function")
            return
            
        panel = JPanel(BorderLayout())
        panel.setBorder(TitledBorder(f"LLM Reverse Helper - Function: {current_function.getName()}"))
        
        # Options panel
        options_panel = JPanel(GridLayout(5, 1, 5, 5))
        
        analyze_button = JButton("Analyze Function Call Chain")
        
        class AnalyzeActionListener(java.awt.event.ActionListener):
            def __init__(self, helper, function):
                self.helper = helper
                self.function = function
            def actionPerformed(self, event):
                self.helper.process_function_chain(self.function)
                
        analyze_button.addActionListener(AnalyzeActionListener(self, current_function))
        options_panel.add(analyze_button)
        
        rename_vars_button = JButton("Rename Variables in Current Function")
        
        class RenameVarsActionListener(java.awt.event.ActionListener):
            def __init__(self, helper, function):
                self.helper = helper
                self.function = function
            def actionPerformed(self, event):
                self.helper.rename_variables_in_function(self.function)
                
        rename_vars_button.addActionListener(RenameVarsActionListener(self, current_function))
        options_panel.add(rename_vars_button)
        
        identify_algo_button = JButton("Identify Algorithms in Current Function")
        
        class IdentifyAlgoActionListener(java.awt.event.ActionListener):
            def __init__(self, helper, function):
                self.helper = helper
                self.function = function
            def actionPerformed(self, event):
                self.helper.identify_algorithms(self.function)
                
        identify_algo_button.addActionListener(IdentifyAlgoActionListener(self, current_function))
        options_panel.add(identify_algo_button)
        
        analyze_protections_button = JButton("Analyze Binary Protections")
        
        class AnalyzeProtectionsActionListener(java.awt.event.ActionListener):
            def __init__(self, helper):
                self.helper = helper
            def actionPerformed(self, event):
                self.helper.analyze_binary_protections()
                
        analyze_protections_button.addActionListener(AnalyzeProtectionsActionListener(self))
        options_panel.add(analyze_protections_button)
        
        config_button = JButton("Configure LLM Connection")
        
        class ConfigActionListener(java.awt.event.ActionListener):
            def __init__(self, helper):
                self.helper = helper
            def actionPerformed(self, event):
                self.helper.show_config_dialog()
                
        config_button.addActionListener(ConfigActionListener(self))
        options_panel.add(config_button)
        
        panel.add(options_panel, BorderLayout.CENTER)
        
        askDialog(panel, "LLM Reverse Helper")

# Main entry point
def main():
    try:
        helper = LLMReverseHelper()
        helper.show_main_menu()
    except Exception as e:
        print(f"[-] Error: {str(e)}")
        traceback.print_exc()

if __name__ == "__main__":
    main()







