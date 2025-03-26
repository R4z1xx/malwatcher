from modules.base import BasePlugin
import os

import aiohttp, hashlib
from typing import Dict
from pathlib import PurePosixPath
from urllib.parse import urlparse, urlunparse, urljoin

class VirusTotal(BasePlugin):
    def __init__(self):
        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        super().__init__(config_path)
        self.report_url = "https://www.virustotal.com/gui/"
        self.api_base_url = "https://www.virustotal.com/api/v3/"

    async def process_ioc(self, ioc_type: str, ioc_value: str) -> Dict:
        '''Process IOC value based on IOC type

        :param ioc_type: IOC type
        :param ioc_value: IOC value
        '''
        handler = {
            'ipv4': self.check_ip,
            'ipv6': self.check_ip,
            'domain': self.check_domain,
            'url': self.check_url,
            'md5': self.check_file,
            'sha1': self.check_file,
            'sha256': self.check_file
        }.get(ioc_type)
        
        if not handler:
            return {'status': False, 'error': f'Unsupported IOC type: {ioc_type}'}
        
        try:
            return await handler(ioc_value)
        except Exception as e:
            return {'status': False, 'error': str(e)}

    async def _make_request(self, endpoint: str) -> Dict:
        '''Make request to VT API

        :param endpoint: API endpoint + IOC value
        '''
        async with aiohttp.ClientSession() as session:
            headers = {"accept": "application/json", "x-apikey": self.api_key}
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

    def _get_score(self, vt_response: Dict) -> str:
        '''Get VT score from response

        :param vt_response: VirusTotal response
        '''
        try:
            stats = vt_response['data']['attributes']['last_analysis_stats']
            return "{}/{}".format(stats.get('malicious', 0), sum(stats.values(), 0))
        except KeyError:
            return "0/0"

    def _vt_url_hash(self, url: str) -> str:
        '''Generate VirusTotal URL identifier
        '''
        canonicalized = self._canonicalize_url(url)
        return hashlib.sha256(canonicalized.encode()).hexdigest()

    def _canonicalize_url(self, url: str) -> str:
        '''VT URL normalization according to their documentation
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

    async def check_ip(self, ip_address):
        response = await self._make_request(str(PurePosixPath('ip_addresses', ip_address)))
        if not response or 'data' not in response:
            return {'status': False}
        
        return {
            'status': True,
            'vt_score': self._get_score(response),
            'as_owner': response['data']['attributes'].get('as_owner', 'N/A'),
            'country': response['data']['attributes'].get('country', 'N/A'),
            **({'crowdsourced_context': response['data']['attributes'].get('crowdsourced_context', [{}])[0].get('details')} if response['data']['attributes'].get('crowdsourced_context', [{}])[0].get('details') else {}),
            'vt_link': urljoin(self.report_url, str(PurePosixPath('ip-address', ip_address)))
        }

    async def check_domain(self, domain):
        response = await self._make_request(str(PurePosixPath('domains', domain)))
        if not response or 'data' not in response:
            return {'status': False}
        
        return {
            'status': True,
            'vt_score': self._get_score(response),
            **({'crowdsourced_context': response['data']['attributes'].get('crowdsourced_context', [{}])[0].get('details')} if response['data']['attributes'].get('crowdsourced_context', [{}])[0].get('details') else {}),
            'vt_link': urljoin(self.report_url, str(PurePosixPath('domain', domain)))
        }

    async def check_url(self, url):
        url_hash = self._vt_url_hash(url)
        response = await self._make_request(str(PurePosixPath('urls', url_hash)))
        if not response or 'data' not in response:
            return {'status': False}
        
        return {
            'status': True,
            'vt_score': self._get_score(response),
            **({'crowdsourced_context': response['data']['attributes'].get('crowdsourced_context', [{}])[0].get('details')} if response['data']['attributes'].get('crowdsourced_context', [{}])[0].get('details') else {}),
            'vt_link': urljoin(self.report_url, str(PurePosixPath('url', url_hash)))
        }

    async def check_file(self, file_hash):
        response = await self._make_request(str(PurePosixPath('files', file_hash)))
        if not response or 'data' not in response:
            return {'status': False}
        
        return {
            'status': True,
            'vt_score': self._get_score(response),
            'popular_threat_classification': response['data']['attributes'].get('popular_threat_classification', {}).get('suggested_threat_label', 'N/A'),
            **({'crowdsourced_context': response['data']['attributes'].get('crowdsourced_context', [{}])[0].get('details')} if response['data']['attributes'].get('crowdsourced_context', [{}])[0].get('details') else {}),
            'vt_link': urljoin(self.report_url, str(PurePosixPath('file', file_hash)))
        }