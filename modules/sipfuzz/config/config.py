import json
import os
from typing import Dict, Any

class SipFuzzConfig:
    def __init__(self):
        self.config_file = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'config', 'sipfuzz_config.json')
        self.config_dir = os.path.dirname(self.config_file)
        self.default_config = {
            'ip': '',
            'port': '5060',
            'proto': 'UDP',
            'proxy': '',
            'from_user': '1000',
            'to_user': '1000',
            'verbose': '0',
            'delay': 0
        }
        self.config = self.load_config()

    def ensure_config_dir(self):
        """Ensure the config directory exists."""
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)

    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file or return defaults."""
        self.ensure_config_dir()
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    # Ensure all default keys exist
                    for key, value in self.default_config.items():
                        if key not in config:
                            config[key] = value
                    return config
            except (json.JSONDecodeError, IOError):
                print("Error loading config file, using defaults")
                return self.default_config.copy()
        return self.default_config.copy()

    def save_config(self, config: Dict[str, Any]) -> bool:
        """Save configuration to file."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
            return True
        except IOError:
            print("Error saving config file")
            return False

    def get(self, key: str) -> Any:
        """Get a configuration value."""
        return self.config.get(key, self.default_config.get(key))

    def set(self, key: str, value: Any) -> None:
        """Set a configuration value."""
        self.config[key] = value
        self.save_config(self.config)

    def get_all(self) -> Dict[str, Any]:
        """Get all configuration values."""
        return self.config.copy()

# Global configuration instance
config = SipFuzzConfig() 