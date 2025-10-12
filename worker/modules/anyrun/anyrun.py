from modules.base import BasePlugin
import os

from typing import Dict
import aiohttp, hashlib, user_agent
from urllib.parse import urlparse, urlunparse, urljoin

class AnyRun(BasePlugin):
    def __init__(self) -> None:
        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        super().__init__(config_path)
        self.api_base_url = 'https://any.run/report/'

    def _url_hash(self, url: str) -> str:
        '''Generate URL identifier
        '''
        canonicalized = self._canonicalize_url(url)
        return hashlib.sha256(canonicalized.encode()).hexdigest()

    def _canonicalize_url(self, url: str) -> str:
        '''URL normalization
        '''
        url = url.strip()
        parsed = urlparse(url)
        
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        
        if scheme == 'http' and netloc.endswith(':80'):
            netloc = netloc[:-3]
        elif scheme == 'https' and netloc.endswith(':443'):
            netloc = netloc[:-4]
        
        return urlunparse((scheme, netloc, parsed.path.rstrip('/'), parsed.params, parsed.query, ''))

    async def _make_request(self, ioc_hash: str) -> str:
        '''Make request to Anyrun

        :param endpoint: API endpoint
        '''
        async with aiohttp.ClientSession() as session:
            headers = {'user-agent': user_agent.generate_user_agent(os=('win', 'linux'))}
            try:
                async with session.head(
                    urljoin(self.api_base_url, ioc_hash),
                    headers=headers,
                    timeout=10,
                    allow_redirects=True  # Follow redirects to detect 404 pages
                ) as response:
                    response.raise_for_status()
                    return {'url': response.history[0].url.name if response.history else ''}
            except aiohttp.ClientResponseError as e:
                return {'error': "HTTP error: {} {}".format(e.status, e.message)}
            except aiohttp.ClientError as e:
                return {'error': "Connection error: {}".format(str(e))}

    async def process_ioc(self, ioc_type: str, ioc_value: str) -> Dict:
        '''Check IOC in Anyrun

        :param ioc: IOC to check
        :param type: Type of IOC
        '''
        if ioc_type not in self.supported_iocs:
            return {'status': False, 'error': f'Unsupported IOC type: {ioc_type}'}

        if ioc_type in ['url', 'domain']:
            ioc_value = self._url_hash(ioc_value)

        response = await self._make_request(ioc_value)
        # Check if the response exists or if its an empty string
        if not response or response.get('url', '') == '':
            return {'status': False}
        
        return {
            'status': True,
            'anyrun_link': urljoin(self.api_base_url, response.get('url', 'N/A'))
        }