#!/usr/bin/env python3

import os
import importlib.util
import sys
from typing import Dict, Callable, Optional

# Global fuzzer instance

def load_modules() -> Dict[str, Callable]:
    """Load all modules from the modules directory and its subdirectories."""
    modules = {}
    modules_dir = os.path.join(os.path.dirname(__file__), 'modules')
    print(f"\nScanning for modules in: {modules_dir}")
    
    def load_module_from_path(file_path: str, module_name: str) -> None:
        """Load a single module from its file path."""
        try:
            print(f"Attempting to load module: {module_name} from {file_path}")
            
            # Add the modules directory to sys.path if it's not already there
            if modules_dir not in sys.path:
                sys.path.append(modules_dir)
            
            # Create a proper module spec
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Only add the module if it has a main function
                if hasattr(module, 'main'):
                    modules[module_name] = module
                    print(f"Successfully loaded module: {module_name}")
                else:
                    print(f"Skipping module {module_name}: No main function found")
                    print(f"Available attributes: {dir(module)}")
            else:
                print(f"Failed to load module {module_name}: Invalid spec")
                print(f"Spec: {spec}")
        except Exception as e:
            print(f"Error loading module {module_name}: {str(e)}")
            import traceback
            traceback.print_exc()
            print(f"File path: {file_path}")
            print(f"Module name: {module_name}")
            print(f"sys.path: {sys.path}")
    
    def scan_directory(directory: str) -> None:
        """Scan directory for module directories."""
        print(f"\nScanning directory: {directory}")
        try:
            # First, list all items in the directory
            items = os.listdir(directory)
            print(f"Found items in directory: {items}")
            
            for item in items:
                item_path = os.path.join(directory, item)
                print(f"\nChecking item: {item_path}")
                
                # Skip __pycache__ and other special directories
                if item.startswith('__') or item in ['config', 'fuzz_log']:
                    print(f"Skipping special directory: {item}")
                    continue
                
                if os.path.isdir(item_path):
                    print(f"Found module directory: {item_path}")
                    # Look for Python files that start with 'sip'
                    try:
                        files = os.listdir(item_path)
                        print(f"Files in {item}: {files}")
                        
                        for file in files:
                            file_path = os.path.join(item_path, file)
                            print(f"Checking file: {file_path}")
                            
                            if file.startswith('sip') and file.endswith('.py'):
                                print(f"Found matching module file: {file_path}")
                                # Use the file name without extension as the module name
                                module_name = os.path.splitext(file)[0]
                                load_module_from_path(file_path, module_name)
                                break  # Only load the first matching file
                    except Exception as e:
                        print(f"Error scanning module directory {item_path}: {str(e)}")
                        import traceback
                        traceback.print_exc()
        except Exception as e:
            print(f"Error scanning directory {directory}: {str(e)}")
            import traceback
            traceback.print_exc()
    
    # Start scanning from the modules directory
    scan_directory(modules_dir)
    print(f"\nLoaded modules: {list(modules.keys())}")
    input("\nPress Enter to continue to menu...")
    return modules

def clear_screen():
    """Clear the terminal screen."""
    os.system('clear' if os.name == 'posix' else 'cls')

def display_menu(modules: Dict[str, Callable]) -> None:
    """Display the main menu with available modules."""
    clear_screen()
    print("=== SIPACT Main Menu ===")
    print("\nAvailable Modules:")
    
    # Sort modules by name
    sorted_modules = sorted(modules.keys())
    
    # Display modules
    for i, module_name in enumerate(sorted_modules, 1):
        print(f"{i}. {module_name}")
    
    print(f"{len(modules) + 1}. Exit")
    print("\nSelect an option: ", end='')

def main():
    modules = load_modules()
    
    while True:
        display_menu(modules)
        
        try:
            choice = input().strip()
            if choice.lower() in ['q', 'quit', 'exit']:
                break
                
            choice = int(choice)
            if choice == len(modules) + 1:  # Exit option
                break
            elif 1 <= choice <= len(modules):
                module_name = sorted(modules.keys())[choice - 1]
                module = modules[module_name]
                
                try:
                    # Execute the module's main function if it exists
                    if hasattr(module, 'main'):
                        module.main()
                    else:
                        print(f"\nModule {module_name} does not have a main function.")
                    
                    input("\nPress Enter to return to main menu...")
                except Exception as e:
                    print(f"\nError executing module {module_name}: {str(e)}")
                    input("\nPress Enter to return to main menu...")
            else:
                print("\nInvalid choice. Please try again.")
                input("\nPress Enter to continue...")
                
        except ValueError:
            print("\nPlease enter a valid number.")
            input("\nPress Enter to continue...")
        except KeyboardInterrupt:
            print("\n\nExiting...")
            break

if __name__ == "__main__":
    main()
