from modules.base import BasePlugin
import os

from typing import Dict
from pathlib import PurePosixPath
from urllib.parse import urljoin, quote_plus
import aiohttp

class InQuestDFI(BasePlugin):
    def __init__(self) -> None:
        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        super().__init__(config_path)
        self.report_url = "https://labs.inquest.net/dfi/"
        self.api_base_url = "https://labs.inquest.net/api/dfi/search/"
    
    async def _make_request(self, endpoint: str, params: Dict) -> Dict:
        '''Make request to InQuest DFI API

        :param endpoint: API endpoint
        '''
        async with aiohttp.ClientSession() as session:
            headers = {"accept": "application/json", "Authorization": f"Bearer {self.api_key}"}
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
            'ipv4': self._check_dfi_ioc,
            'ipv6': self._check_dfi_ioc,
            'domain': self._check_dfi_ioc,
            'url': self._check_dfi_ioc,
            'md5': self._check_dfi_hash,
            'sha1': self._check_dfi_hash,
            'sha256': self._check_dfi_hash
        }.get(ioc_type)
        
        if not handler:
            return {'status': False, 'error': f'Unsupported IOC type: {ioc_type}'}
        
        try:
            return await handler(ioc_type, ioc_value)
        except Exception as e:
            return {'status': False, 'error': str(e)}

    async def _check_dfi_hash(self, ioc_type: str, hash: str) -> Dict:
        if ioc_type not in ['md5', 'sha1', 'sha256']:
            return {'status': False, 'error': f'Unsupported hash type: {ioc_type}'}

        response = await self._make_request(endpoint=str(PurePosixPath('hash', ioc_type)), params={"hash": hash})
        if not response or not response.get('data'):
            return {'status': False}
        
        descriptions = []
        for alerts in response['data'][0].get('inquest_alerts', []):
            descriptions.append(alerts.get('description'))
        return {
            'status': True,
            'classification': response.get('data')[0].get('classification', 'N/A'),
            'first_seen': response.get('data')[0].get('first_seen', 'N/A').replace('T', ' '),
            'descriptions': descriptions[:5],
            'mime_type': response.get('data')[0].get('mime_type', 'N/A'),
            'inquest_link': urljoin(self.report_url, str(PurePosixPath('sha256', response.get('data')[0].get('sha256', 'N/A'))))
        }
    
    async def _check_dfi_ioc(self, ioc_type: str, ioc: str) -> Dict:
        if ioc_type not in ['ipv4', 'ipv6', 'domain', 'url']:
            return {'status': False, 'error': f'Unsupported IOC type: {ioc_type}'}
        
        if ioc_type in ['ipv4', 'ipv6']:
            ioc_type = 'ip'
        
        response = await self._make_request(endpoint=str(PurePosixPath('ioc', ioc_type)), params={"keyword": ioc})
        if not response or not response.get('data'):
            return {'status': False}

        descriptions = []
        for alerts in response['data'][0].get('inquest_alerts', []):
            descriptions.append(alerts.get('description'))
        return {
            'status': True,
            'classification': response.get('data')[0].get('classification', 'N/A'),
            'first_seen': response.get('data')[0].get('first_seen', 'N/A').replace('T', ' '),
            'descriptions': descriptions[:5],
            'mime_type': response.get('data')[0].get('mime_type', 'N/A'),
            'inquest_link': urljoin(self.report_url, str(PurePosixPath('sha256', response.get('data')[0].get('sha256', 'N/A'))))
        }

class InQuestIOCDB(BasePlugin):
    def __init__(self) -> None:
        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        super().__init__(config_path)
        self.report_url = "https://labs.inquest.net/iocdb/search/"
        self.api_base_url = "https://labs.inquest.net/api/iocdb/search"

    async def _make_request(self, endpoint: str, params: Dict) -> Dict:
        '''Make request to InQuest IOCDB API

        :param endpoint: API endpoint
        '''
        async with aiohttp.ClientSession() as session:
            headers = {"accept": "application/json", "Authorization": f"Bearer {self.api_key}"}
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
        '''Process IOC value based on IOC type'

        :param ioc_type: IOC type
        :param ioc_value: IOC value
        '''
        if ioc_type not in self.supported_iocs:
            return {'status': False, 'error': f'Unsupported IOC type: {ioc_type}'}

        response = await self._make_request(self.api_base_url, params={"keyword": ioc_value})
        if not response or not response.get('data'):
            return {'status': False}

        nb_found = len(response.get('data', []))
        return {
            'status': True,
            'nb_found': f"{nb_found}+" if nb_found == 1337 else nb_found,
            'first_seen': response.get('data')[0].get('created_date', 'N/A').replace('T', ' '),
            'last_seen': response.get('data')[-1].get('created_date', 'N/A').replace('T', ' '),
            'description': response.get('data')[0].get('reference_text', 'N/A'),
            'iocdb_link': urljoin(self.report_url, str(PurePosixPath('search', quote_plus(ioc_value))))
        }

class InQuestRepDB(BasePlugin):
    def __init__(self) -> None:
        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        super().__init__(config_path)
        self.report_url = "https://labs.inquest.net/repdb/"
        self.api_base_url = "https://labs.inquest.net/api/repdb/search"

    async def _make_request(self, endpoint: str, params: Dict) -> Dict:
        '''Make request to InQuest RepDB API

        :param endpoint: API endpoint
        '''
        async with aiohttp.ClientSession() as session:
            headers = {"accept": "application/json", "Authorization": f"Bearer {self.api_key}"}
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
        '''Process IOC value based on IOC type'

        :param ioc_type: IOC type
        :param ioc_value: IOC value
        '''
        if ioc_type not in self.supported_iocs:
            return {'status': False, 'error': f'Unsupported IOC type: {ioc_type}'}

        response = await self._make_request(self.api_base_url, params={"keyword": ioc_value})
        if not response or not response.get('data'):
            return {'status': False}
        
        nb_found = len(response.get('data', []))
        return {
            'status': True,
            'nb_found': f"{nb_found}+" if nb_found == 1337 else nb_found,
            'first_seen': response.get('data')[0].get('created_date', 'N/A').replace('T', ' '),
            'last_seen': response.get('data')[-1].get('created_date', 'N/A').replace('T', ' '),
            'reputation_source': response.get('data')[0].get('source', 'N/A'),
            'repdb_link': urljoin(self.report_url, str(PurePosixPath('search', quote_plus(ioc_value))))
        }