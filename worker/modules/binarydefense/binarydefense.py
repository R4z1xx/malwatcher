from modules.base import BasePlugin
import os

from typing import Dict
import aiohttp

class BinaryDefense(BasePlugin):
    def __init__(self) -> None:
        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        super().__init__(config_path)
        self.api_base_url = 'https://www.binarydefense.com/banlist.txt'

    async def _make_request(self) -> str:
        '''Make request to Binary Defense

        :param endpoint: API endpoint
        '''
        async with aiohttp.ClientSession() as session:
            headers = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'}
            try:
                async with session.get(
                    self.api_base_url,
                    headers=headers
                ) as response:
                    response.raise_for_status()
                    return await response.text()
            except aiohttp.ClientResponseError as e:
                return {'error': "HTTP error: {} {}".format(e.status, e.message)}
            except aiohttp.ClientError as e:
                return {'error': "Connection error: {}".format(str(e))}

    async def process_ioc(self, ioc_type: str, ioc_value: str) -> Dict:
        '''Check IPs in Binary Defense banlist

        :param ioc: IOC to check
        :param type: Type of IOC
        '''
        if ioc_type not in self.supported_iocs:
            return {'status': False, 'error': f'Unsupported IOC type: {ioc_type}'}

        response = await self._make_request()
        if not response or ioc_value not in response:
            return {'status': False}
        
        return {'status': True}