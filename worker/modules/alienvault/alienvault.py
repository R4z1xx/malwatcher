from modules.base import BasePlugin
import os

from typing import Dict
from OTXv2 import OTXv2, IndicatorTypes
from pathlib import PurePosixPath
from urllib.parse import urljoin, quote_plus

class AlienVault(BasePlugin):
    def __init__(self) -> None:
        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        super().__init__(config_path)
        self.report_url = 'https://otx.alienvault.com/indicator/'
        self.api_base_url = 'https://otx.alienvault.com/'
        self.otx = OTXv2(self.api_key, server=self.api_base_url)
        self.otx_ioc_types = {
            'ipv4': IndicatorTypes.IPv4,
            'ipv6': IndicatorTypes.IPv6,
            'domain': IndicatorTypes.DOMAIN,
            'url': IndicatorTypes.URL,
            'md5': IndicatorTypes.FILE_HASH_MD5,
            'sha1': IndicatorTypes.FILE_HASH_SHA1,
            'sha256': IndicatorTypes.FILE_HASH_SHA256
        }
        self.typeOTX = {
            'ipv4': 'ip',
            'ipv6': 'ip',
            'domain': 'domain',
            'url': 'url',
            'md5': 'file',
            'sha1': 'file',
            'sha256': 'file'
        }

    def _make_request(self, type: str, ioc: str) -> Dict:
        '''Make request to AlienVault OTX API
        '''
        try:
            return self.otx.get_indicator_details_by_section(type, ioc, 'general')
        except:
            return None

    def process_ioc(self, ioc_type: str, ioc_value: str) -> Dict:
        '''Check IOC in AlienVault OTX
        
        :param ioc: IOC to check
        :param type: Type of IOC
        '''
        if ioc_type not in self.supported_iocs:
            return {'status': False, 'error': f'Unsupported IOC type: {ioc_type}'}
        
        response = self._make_request(self.otx_ioc_types[ioc_type], ioc_value)
        if not response or (not response.get('base_indicator') and not response.get('asn')):
            return {'status': False}

        return {
            'status': True,
            'pulses_count': response.get('pulse_info', {}).get('count', '0'),
            **({'as_owner': response.get('asn', 'N/A')} if response.get('asn') else {}),
            **({'country': response.get('country_name', 'N/A')} if response.get('country_name') else {}),
            'otx_link': urljoin(self.report_url, str(PurePosixPath(self.typeOTX[ioc_type], quote_plus(ioc_value, safe=':'))))
        }