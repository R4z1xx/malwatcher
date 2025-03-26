from modules.base import BasePlugin
import os

from typing import Dict
from urllib.parse import urljoin
import aiohttp

class Triage(BasePlugin):
    def __init__(self) -> None:
        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        super().__init__(config_path)
        self.report_url = "https://tria.ge/"
        self.api_base_url = "https://tria.ge/api/v0/search"
    
    async def _make_request(self, endpoint: str) -> Dict:
        '''Make request to Triage API

        :param endpoint: API endpoint
        '''
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            try:
                async with session.get(
                    urljoin(self.api_base_url, endpoint),
                    headers=headers
                ) as response:
                    response.raise_for_status()
                    return await response.json()
            except aiohttp.ClientResponseError as e:
                return {'error': "HTTP error: {} {}".format(e.status, e.message)}
            except aiohttp.ClientError as e:
                return {'error': "Connection error: {}".format(str(e))}


    async def process_ioc(self, ioc_type: str, ioc_value: str) -> Dict:
        '''Check IOC in Triage

        :param ioc_type: IOC type
        :param ioc_value: IOC value
        '''
        if ioc_type not in self.supported_iocs:
            return {'status': False, 'error': f'Unsupported IOC type: {ioc_type}'}

        if ioc_type in ['ipv4']:
            ioc_type = 'ip'
        
        response = await self._make_request("?query={}:{}".format(ioc_type, ioc_value))
        if not response or not response.get('data'):
            return {'status': False}

        return {
            'status': True,
            'related_filename': response.get('data')[0].get('filename', 'N/A'),
            'related_url': response.get('data')[0].get('url', 'N/A'),
            'submitted': response.get('data')[0].get('submitted', 'N/A'),
            'triage_link': urljoin(self.report_url, response.get('data')[0].get('id', 'N/A'))
        }