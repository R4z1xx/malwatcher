from modules.base import BasePlugin
import os

from typing import Dict
from urllib.parse import urljoin
import aiohttp

class Bazaar(BasePlugin):
    def __init__(self) -> None:
        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        super().__init__(config_path)
        self.report_url = "https://bazaar.abuse.ch/sample/"
        self.api_base_url = 'https://mb-api.abuse.ch/api/v1/'
        self.error_tag = ['hash_not_found', 'http_post_expected', 'illegal_hash', 'no_hash_provided']

    async def _make_request(self, data: Dict) -> Dict:
        '''Make request to Bazaar API
        '''
        async with aiohttp.ClientSession() as session:
            headers = {"accept": "application/json", "Auth-Key": self.api_key}
            try:
                async with session.post(
                    self.api_base_url,
                    headers=headers,
                    data=data
                ) as response:
                    response.raise_for_status()
                    return await response.json()
            except aiohttp.ClientResponseError as e:
                return {'error': "HTTP error: {} {}".format(e.status, e.message)}
            except aiohttp.ClientError as e:
                return {'error': "Connection error: {}".format(str(e))}

    async def process_ioc(self, ioc_type: str, ioc_value: str) -> Dict:
        '''Check IOC in Bazaar

        :param ioc: IOC value
        :param type: md5, sha1, sha256
        '''
        if ioc_type not in ['md5', 'sha1', 'sha256']:
            return {'status': False, 'error': f'Unsupported IOC type: {ioc_type}'}

        response = await self._make_request({"query": "get_info", "hash": ioc_value})
        if not response or response.get('query_status', None) in self.error_tag:
            return {'status': False}
        
        return {
            'status': True, 
            'seen_count': len(response['data']),
            'first_seen': response.get('data', [{}])[0].get('first_seen', 'N/A'),
            'last_seen': response.get('data', [{}])[0].get('last_seen', 'N/A'),
            'file_type': response.get('data', [{}])[0].get('file_type_mime', 'N/A'),
            'signature': response.get('data', [{}])[0].get('signature', 'N/A'),
            'tags': response.get('data', [{}])[0].get('tags', 'N/A'),
            'bazaar_link': urljoin(self.report_url, response.get('data', [{}])[0].get('sha256_hash', 'N/A'))
        }

class ThreatFox(BasePlugin):
    def __init__(self) -> None:
        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        super().__init__(config_path)
        self.report_url = "https://threatfox.abuse.ch/ioc/"
        self.api_base_url = 'https://threatfox-api.abuse.ch/api/v1/'
        self.error_tag = ['no_result']

    async def _make_request(self, data: Dict) -> Dict:
        '''Make request to ThreatFox API
        '''
        async with aiohttp.ClientSession() as session:
            headers = {"accept": "application/json", "auth-key": self.api_key}
            try:
                async with session.post(
                    self.api_base_url,
                    headers=headers,
                    json=data
                ) as response:
                    response.raise_for_status()
                    return await response.json()
            except aiohttp.ClientResponseError as e:
                return {'error': "HTTP error: {} {}".format(e.status, e.message)}
            except aiohttp.ClientError as e:
                return {'error': "Connection error: {}".format(str(e))}

    async def process_ioc(self, ioc_type: str, ioc_value: str) -> Dict:
        '''Check IOC in ThreatFox.

        :param ioc: IOC value
        :param type: ipv4, ipv6, domain, URL, md5, sha256
        '''

        if ioc_type not in self.supported_iocs:
            return {'status': False, 'error': f'Unsupported IOC type: {ioc_type}'}

        if ioc_type in ['md5', 'sha256']:
            response = await self._make_request({"query": "search_hash", "hash": ioc_value})
        else:
            response = await self._make_request({"query": "search_ioc", "search_term": ioc_value})
        
        if not response or response.get('query_status', None) in self.error_tag:
            return {'status': False}

        return {
            'status': True,
            'ioc_count': len(response.get('data', [])),
            'first_seen': response.get('data', [{}])[0].get('first_seen', 'N/A'),
            'last_seen': response.get('data', [{}])[0].get('last_seen', 'N/A') if response.get('data', [{}])[0].get('last_seen', 'N/A') else 'N/A',
            'malware_alias': response.get('data', [{}])[0].get('malware_alias', 'N/A').split(",")[:5] if response.get('data', [{}])[0].get('malware_alias', 'N/A') else response.get('data', [{}])[0].get('malware_printable', 'N/A'),
            'threat_description': response.get('data', [{}])[0].get('threat_type_desc', 'N/A'),
            'threatfox_link': urljoin(self.report_url, response.get('data', [{}])[0].get('id', 'N/A'))
        }

class Urlhaus(BasePlugin):
    def __init__(self):
        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        super().__init__(config_path)
        self.api_base_url = 'https://urlhaus-api.abuse.ch/v1/'
        self.error_tag = ['no_results', 'http_post_expected', 'invalid_url', 'invalid_host', 'invalid_sha256', 'invalid_md5']

    async def _make_request(self, endpoint: str, data: Dict) -> Dict:
        '''Make request to URLhaus API
        '''
        async with aiohttp.ClientSession() as session:
            headers = {"accept": "application/json", "auth-key": self.api_key}
            try:
                async with session.post(
                    urljoin(self.api_base_url, endpoint),
                    headers=headers,
                    data=data
                ) as response:
                    response.raise_for_status()
                    return await response.json()
            except aiohttp.ClientResponseError as e:
                return {'error': "HTTP error: {} {}".format(e.status, e.message)}
            except aiohttp.ClientError as e:
                return {'error': "Connection error: {}".format(str(e))}

    async def process_ioc(self, ioc_type: str, ioc_value: str) -> Dict:
        '''Check IOC in URLhaus.

        :param ioc: IOC value
        :param type: ipv4, ipv6, url, domain, md5, sha256
        '''
        handler = {
            'ipv4': self._check_domain_ip,
            'ipv6': self._check_domain_ip,
            'domain': self._check_domain_ip,
            'url': self._check_url,
            'md5': self._check_hash,
            'sha1': self._check_hash,
            'sha256': self._check_hash
        }.get(ioc_type)

        if not handler:
            return {'status': False, 'error': f'Unsupported IOC type: {ioc_type}'}
        
        try:
            return await handler(ioc_type, ioc_value)
        except Exception as e:
            return {'status': False, 'error': str(e)}

    async def _check_url(self, ioc_type: str, url: str) -> Dict:
        response = await self._make_request('url', {"url": url})
        if not response or response.get('query_status', None) in self.error_tag:
            return {'status': False}

        return {
            'status': True, 
            'url_status': response.get('url_status', 'N/A'),
            'last_online': response.get("last_online", 'N/A') if response.get('url_status', None) == "offline" else 'N/A',
            'threat': response.get('threat', 'N/A'),
            **({'tags': response['tags'][:5]} if response.get('tags') else {}),
            'payloads': 'Yes' if response.get('payloads', None) else 'No',
            'urlhaus_link': response.get('urlhaus_reference', 'N/A')
        }

    
    async def _check_domain_ip(self, ioc_type: str, ioc: str) -> Dict:
        response = await self._make_request('host', {"host": ioc})
        if not response or response.get('query_status', None) in self.error_tag:
            return {'status': False}
        
        return {
            'status': True, 
            'url_count': response.get('url_count', '0'), # Number of URLs observed on this host
            'blacklist': response.get('blacklist', {}).get('spamhaus_dbl', 'N/A'),
            'urlhaus_link': response.get('urlhaus_reference', 'N/A')
        }
    
    async def _check_hash(self, ioc_type: str, hash: str) -> Dict:
        response = await self._make_request('payload', {'{}_hash'.format(ioc_type): hash})
        if not response or response.get('query_status', None) in self.error_tag:
            return {'status': False}
        
        return {
            'status': True, 
            'signature': response.get('signature', 'N/A'), # Malware Family
            'file_type': response.get('file_type', 'N/A'),
            'first_seen': response.get('firstseen', 'N/A'),
            'last_seen': response.get('lastseen', 'N/A'),
            'url_count': response.get('url_count', '0'),
            'urlhaus_link': response.get('urlhaus_reference', 'N/A')
        }