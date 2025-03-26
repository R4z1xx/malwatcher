from abc import ABC, abstractmethod
import yaml

class BasePlugin(ABC):
    def __init__(self, config_path):
        self.config = self.load_config(config_path)
        self.api_key = self.config.get('api_key', None)
        self.enabled = self.config.get('enabled', False)
        self.supported_iocs = self.config.get('supported_iocs', [])
        
    def load_config(self, config_path):
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def is_enabled(self):
        return self.enabled
    
    def supports_ioc_type(self, ioc_type):
        return ioc_type.lower() in [ioc.lower() for ioc in self.supported_iocs]
    
    @abstractmethod
    def process_ioc(self, ioc_type, ioc_value):
        pass