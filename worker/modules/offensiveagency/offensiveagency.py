from modules.base import BasePlugin
import os, json

from typing import Dict
from pathlib import PurePosixPath
from urllib.parse import urljoin
import aiohttp

class OffensiveAgency(BasePlugin):
    def __init__(self):
        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        super().__init__(config_path)
        self.report_base_url = "https://offensive.agency/host/"
        self.api_base_url = "https://offensive.agency/api/"

    async def _make_request(self, ioc_value: str) -> Dict:
        """Make a request to the OffensiveAgency API.

        :param ioc_value: IOC value to look up
        """
        async with aiohttp.ClientSession() as session:

            try:
                async with session.get(
                    urljoin(self.api_base_url, ioc_value),
                ) as response:
                    response.raise_for_status()
                    return await response.json()
            except aiohttp.ClientResponseError as e:
                return {"error": "HTTP error: {} {}".format(e.status, e.message)}
            except aiohttp.ClientError as e:
                return {"error": "Connection error: {}".format(str(e))}

    async def process_ioc(self, ioc_type: str, ioc_value: str) -> Dict:
        """Check an IOC against OffensiveAgency.

        :param ioc_type: Type of the IOC (must be in self.supported_iocs)
        :param ioc_value: IOC value to check
        """
        if ioc_type not in self.supported_iocs:
            return {"status": False, "error": f"Unsupported IOC type: {ioc_type}"}

        match ioc_type:
            case 'ipv4':
                ioc_infos = await self.check_ip(ioc_value)
            case 'domain':
                ioc_infos = await self.check_domain(ioc_value)
            case _:
                return {"status": False, "error": f"Unsupported IOC type: {ioc_type}"}

        if not ioc_infos:
            return {"status": False}
        if "error" in ioc_infos:
            return {"status": False, "error": ioc_infos["error"]}

        return {
            "status": True,
            'first_seen': ioc_infos.get('first_seen', 'N/A'),
            'last_seen': ioc_infos.get('last_seen', 'N/A'),
            "country": ioc_infos.get("country", "N/A"),
            "as_owner": ioc_infos.get("org", "N/A"),
            "tags": list(ioc_infos["families"])[:5] if ioc_infos.get("families") is not None else "N/A",
            "report_link": urljoin(self.report_base_url, ioc_infos.get("ip", "")) if ioc_infos.get("ip", "") else "N/A",
        }

    def search_ioc_list(self, ioc: str, ioc_list: str) -> bool:
        '''Search for indicator in retrieved indicator list

        :param ioc: IP or Domain
        :param ioc_list: retrieved data from ips.txt or domains.txt
        '''
        if not ioc or not ioc_list:
            return False

        for entry in ioc_list.splitlines():
            if entry == ioc:
                return True

        return False

    def search_domain(self, domain: str, data: str | list) -> dict | None:
        '''Search for a domain in retrieved host data

        :param domain: domain to look for
        :param data: raw text of the file
        '''
        objects = json.loads(data) if isinstance(data, str) else data

        for item in objects:
            if any(domain.get('name', '') == domain for domain in item.get('domains', [])):
                return item
        return None

    async def check_ip(self, ip_address: str) -> Dict:
        ioc_infos = await self._make_request(str(PurePosixPath('host', ip_address)))
        if "error" in ioc_infos and "HTTP error: 404" in ioc_infos:
            ioc_infos = {}
        return ioc_infos

    async def check_domain(self, domain: str) -> Dict:
        ioc_list = await self._make_request('domains.txt')
        if not ioc_list or not self.search_ioc_list(domain, ioc_list):
            return {}

        host_list = self._make_request('hosts.json')

        if ioc_infos := self.search_domain(domain, host_list):
            return ioc_infos
        return {}
