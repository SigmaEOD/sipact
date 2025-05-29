import os
from typing import Dict, Any, Optional

def parse_config(config_file: str) -> Dict[str, Any]:
    """
    Parse a configuration file and return its contents as a dictionary.
    
    Args:
        config_file (str): Path to the configuration file
        
    Returns:
        Dict[str, Any]: Dictionary containing configuration values
    """
    parser = ConfigParser(config_file)
    return parser.parse()

def save_config(config_file: str, config: Dict[str, Any]) -> None:
    """
    Save configuration values to a file.
    
    Args:
        config_file (str): Path to the configuration file
        config (Dict[str, Any]): Dictionary containing configuration values
    """
    with open(config_file, 'w') as f:
        for key, value in config.items():
            f.write(f"{key}:: {value}\n")

class ConfigParser:
    def __init__(self, config_file: str):
        """
        Initialize the config parser with a config file path.
        
        Args:
            config_file (str): Path to the configuration file
        """
        self.config_file = config_file
        self.config = {}
        
    def parse(self) -> Dict[str, Any]:
        """
        Parse the configuration file and return a dictionary of key-value pairs.
        
        Returns:
            Dict[str, Any]: Dictionary containing configuration values
        """
        if not os.path.exists(self.config_file):
            raise FileNotFoundError(f"Configuration file not found: {self.config_file}")
            
        with open(self.config_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                    
                if '::' not in line:
                    continue
                    
                key, value = line.split('::', 1)
                key = key.strip()
                value = value.strip()
                
                # Try to convert value to appropriate type
                if value.lower() == 'true':
                    value = True
                elif value.lower() == 'false':
                    value = False
                elif value.isdigit():
                    value = int(value)
                elif value.replace('.', '', 1).isdigit() and value.count('.') == 1:
                    value = float(value)
                    
                self.config[key] = value
                
        return self.config
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value by key.
        
        Args:
            key (str): Configuration key
            default (Any, optional): Default value if key is not found
            
        Returns:
            Any: Configuration value or default if not found
        """
        return self.config.get(key, default)
    
    def get_int(self, key: str, default: Optional[int] = None) -> Optional[int]:
        """
        Get a configuration value as integer.
        
        Args:
            key (str): Configuration key
            default (int, optional): Default value if key is not found or not an integer
            
        Returns:
            Optional[int]: Integer configuration value or default if not found/invalid
        """
        value = self.get(key, default)
        try:
            return int(value) if value is not None else default
        except (ValueError, TypeError):
            return default
    
    def get_float(self, key: str, default: Optional[float] = None) -> Optional[float]:
        """
        Get a configuration value as float.
        
        Args:
            key (str): Configuration key
            default (float, optional): Default value if key is not found or not a float
            
        Returns:
            Optional[float]: Float configuration value or default if not found/invalid
        """
        value = self.get(key, default)
        try:
            return float(value) if value is not None else default
        except (ValueError, TypeError):
            return default
    
    def get_bool(self, key: str, default: Optional[bool] = None) -> Optional[bool]:
        """
        Get a configuration value as boolean.
        
        Args:
            key (str): Configuration key
            default (bool, optional): Default value if key is not found or not a boolean
            
        Returns:
            Optional[bool]: Boolean configuration value or default if not found/invalid
        """
        value = self.get(key, default)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ('true', 'yes', '1', 'y')
        return default 