from modules.base import BasePlugin
import os

from typing import Dict
from apiosintDS import apiosintDS

class DigitalSide(BasePlugin):
    def __init__(self) -> None:
        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        super().__init__(config_path)
        self.typeDS = {
            'ipv4': 'ip',
            'domain': 'domain',
            'url': 'url',
            'md5': 'hash',
            'sha1': 'hash',
            'sha256': 'hash'
        }

    def _make_request(self, ioc):
        '''Make request to DigitalSide API
        '''
        try:
            return apiosintDS.request(entities=[ioc])
        except:
            return None
    
    def process_ioc(self, ioc_type: str, ioc_value: str) -> Dict:
        '''Check IOC in DigitalSide

        :param ioc: IOC to check
        :param type: Type of IOC
        '''
        if ioc_type not in self.supported_iocs:
            return {'status': False, 'error': f'Unsupported IOC type: {ioc_type}'}
        
        response = self._make_request(ioc_value)
        if not response or not response.get('generalstatistics', {}).get('itemsFound', 0):
            return {'status': False}

        return {
            'status': True,
            'ds_link': response.get(self.typeDS[ioc_type], {}).get('items', [{}])[0].get('online_reports', {}).get('OSINTDS_REPORT', None)
        }