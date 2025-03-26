from modules.base import BasePlugin
import os

from typing import Dict
from urllib.parse import urljoin, quote_plus
import aiohttp

class AbuseIPDB(BasePlugin):
    def __init__(self):
        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        super().__init__(config_path)
        self.report_url = "https://www.abuseipdb.com/check/"
        self.api_base_url = "https://api.abuseipdb.com/api/v2/check"

    async def process_ioc(self, ioc_type: str, ioc_value: str) -> Dict:
        '''Check IOC in AbuseIPDB
        
        :param ioc: IOC to check
        :param type: Type of IOC
        '''
        if ioc_type not in self.supported_iocs:
            return {'status': False, 'error': f'Unsupported IOC type: {ioc_type}'}
        
        response = await self._make_request(ioc_value)
        if not response:
            return {'status': False}
        elif 'error' in response:
            return {'status': False, 'error': response['error']}
        
        return {
            'status': True,
            'score': response['data'].get('abuseConfidenceScore', 'N/A'),
            'country': response['data'].get('countryCode', 'N/A'),
            'as_owner': response['data'].get('isp', 'N/A'),
            'report_count': len(response['data'].get('reports', [])),
            'abuseipdb_link': urljoin(self.report_url, quote_plus(ioc_value))
        }

    async def _make_request(self, ip_address: str) -> Dict:
        '''Make request to AbuseIPDB API

        :param endpoint: API endpoint
        '''
        async with aiohttp.ClientSession() as session:
            headers = {"accept": "application/json", "Key": self.api_key}
            try:
                async with session.get(
                    self.api_base_url,
                    params={"ipAddress": ip_address},
                    headers=headers
                ) as response:
                    response.raise_for_status()
                    return await response.json()
            except aiohttp.ClientResponseError as e:
                return {'error': "HTTP error: {} {}".format(e.status, e.message)}
            except aiohttp.ClientError as e:
                return {'error': "Connection error: {}".format(str(e))}
    