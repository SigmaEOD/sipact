import os
from typing import Dict, Any

def get_config_path(module_name: str) -> str:
    """Get the path to the module's config file."""
    return os.path.join(os.path.dirname(os.path.dirname(__file__)), 'modules', module_name, 'config', 'config.txt')

def parse_config(module_name: str) -> Dict[str, Any]:
    """Parse a simple key::value config file for a specific module."""
    config = {}
    config_path = get_config_path(module_name)
    
    if not os.path.exists(config_path):
        print(f"Warning: Config file not found at {config_path}")
        return config
        
    with open(config_path, 'r') as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
                
            # Parse key::value pairs
            if '::' in line:
                key, value = line.split('::', 1)
                key = key.strip()
                value = value.strip()
                
                # Remove quotes if present
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]
                    
                # Convert numeric values
                if value.isdigit():
                    value = int(value)
                elif value.replace('.', '', 1).isdigit():
                    value = float(value)
                    
                config[key] = value
                
    return config

def save_config(module_name: str, config: Dict[str, Any]) -> bool:
    """Save configuration to module's config file."""
    config_path = get_config_path(module_name)
    
    try:
        # Ensure config directory exists
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        
        with open(config_path, 'w') as f:
            # Write header
            f.write(f"# {module_name.upper()} Configuration\n")
            f.write("# Format: key::value\n")
            f.write("# Comments start with #\n\n")
            
            # Group settings by category
            categories = {
                'Target Configuration': ['ip_addr', 'port', 'proto', 'proxy'],
                'User Configuration': ['from_user', 'to_user', 'user_agent'],
                'Fuzzing Configuration': ['verbose', 'delay', 'max_requests', 'timeout'],
                'Logging Configuration': ['log_dir', 'log_level']
            }
            
            for category, keys in categories.items():
                f.write(f"# {category}\n")
                for key in keys:
                    if key in config:
                        value = config[key]
                        # Add quotes for string values
                        if isinstance(value, str):
                            value = f'"{value}"'
                        f.write(f"{key}::{value}\n")
                f.write("\n")
                
        return True
    except IOError as e:
        print(f"Error saving config file: {str(e)}")
        return False 