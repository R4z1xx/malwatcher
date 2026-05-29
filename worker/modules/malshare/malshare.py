from modules.base import BasePlugin
import os

from typing import Dict
from urllib.parse import quote_plus
import aiohttp
from datetime import datetime

class Malshare(BasePlugin):
    def __init__(self):
        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        super().__init__(config_path)
        self.report_url = "https://malshare.com/sample.php"
        self.api_base_url = "https://malshare.com/api.php"

    async def _make_request(self, ioc_value: str) -> Dict:
        '''Make request to Malshare API

        :param ioc_value: IOC value to check
        '''
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            try:
                async with session.get(
                    self.api_base_url,
                    params={"api_key": self.api_key, "action": "search", "query": ioc_value},
                    headers=headers
                ) as response:
                    response.raise_for_status()
                    return await response.json()
            except aiohttp.ClientResponseError as e:
                return {'error': "HTTP error: {} {}".format(e.status, e.message)}
            except aiohttp.ClientError as e:
                return {'error': "Connection error: {}".format(str(e))}

    async def process_ioc(self, ioc_type: str, ioc_value: str) -> Dict:
        '''Check IOC in Malshare
        
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
            'filetype': response[0].get('type', 'N/A'),
            'uploaded': datetime.fromtimestamp(int(response[0].get('added', 0))).strftime('%Y-%m-%d %H:%M:%S') if response[0].get('added') else 'N/A',
            'malshare_link': "{}?action=detail&hash={}".format(self.report_url, quote_plus(ioc_value))
        }