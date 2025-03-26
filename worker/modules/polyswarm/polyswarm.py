from modules.base import BasePlugin
import os

from typing import Dict
from pathlib import PurePosixPath
from urllib.parse import urljoin
import aiohttp

class PolySwarm(BasePlugin):
    def __init__(self) -> None:
        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        super().__init__(config_path)
        self.api_base_url = "https://api.polyswarm.network/v3/search/"
    
    async def _make_request(self, endpoint: str, params: Dict) -> Dict:
        '''Make request to PolySwarm API

        :param endpoint: API endpoint
        :param params: Request parameters
        '''
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": self.api_key}
            try:
                async with session.get(
                    urljoin(self.api_base_url, endpoint),
                    params=params,
                    headers=headers
                ) as response:
                    response.raise_for_status()
                    return await response.json()
            except aiohttp.ClientResponseError as e:
                return {'error': "HTTP error: {} {}".format(e.status, e.message)}
            except aiohttp.ClientError as e:
                return {'error': "Connection error: {}".format(str(e))}

    async def process_ioc(self, ioc_type: str, ioc_value: str) -> Dict:
        '''Process IOC value based on IOC type

        :param ioc_type: IOC type
        :param ioc_value: IOC value
        '''
        handler = {
            'url': self._search_url,
            'md5': self._search_hash,
            'sha1': self._search_hash,
            'sha256': self._search_hash
        }.get(ioc_type)
        
        if not handler:
            return {'status': False, 'error': f'Unsupported IOC type: {ioc_type}'}
        
        try:
            return await handler(ioc_type, ioc_value)
        except Exception as e:
            return {'status': False, 'error': str(e)}

    async def _search_url(self, ioc_type: str, url: str) -> Dict:
        if ioc_type not in ['url']:
            return {'status': False, 'error': f'Unsupported hash type: {ioc_type}'}
        
        params = {
            "url": url, 
            "community": "default"
        }
        response = await self._make_request(endpoint='url', params=params)
        if not response or not response.get('result') or 'error' in response:
            return {'status': False}
        
        score = int(response.get('result')[0].get('polyscore') * 100)
        return {
            'status': True,
            'score': f'{score}%',
            'first_seen': response.get('result')[0].get('first_seen'),
            'last_seen': response.get('result')[0].get('last_seen'),
            'last_scanned': response.get('result')[0].get('last_scanned'),
            'detections': response.get('result')[0].get('detections'), # Contains Dict with: Benign, Malicious, Total
            'polyswarm_link': response.get('result')[0].get('permalink')
        }

    async def _search_hash(self, ioc_type: str, hash: str) -> Dict:
        if ioc_type not in ['md5', 'sha1', 'sha256']:
            return {'status': False, 'error': f'Unsupported hash type: {ioc_type}'}
        
        params = {
            "hash": hash, 
            "community": "default"
        }
        response = await self._make_request(endpoint=str(PurePosixPath('hash', ioc_type)), params=params)

        if not response or not response.get('result') or 'error' in response:
            return {'status': False}

        score = int(response.get('result')[0].get('polyscore') * 100)
        return {
            'status': True,
            'score': f'{score}%',
            'extended_type': response.get('result')[0].get('extended_type'),
            'mime_type': response.get('result')[0].get('mimetype'),
            'first_seen': response.get('result')[0].get('first_seen'),
            'last_seen': response.get('result')[0].get('last_seen'),
            'last_scanned': response.get('result')[0].get('last_scanned'),
            'detections': response.get('result')[0].get('detections'), # Contains Dict with : Benign, Malicious, Total
            'polyswarm_link': response.get('result')[0].get('permalink')
        }