from modules.base import BasePlugin
import os

from typing import Dict
from urllib.parse import urljoin
import aiohttp

class Rosti(BasePlugin):
    def __init__(self):
        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        super().__init__(config_path)
        self.report_base_url = "https://rosti.dev/reports/"
        self.api_base_url = "https://api.rosti.dev/v2/"

    async def _make_request(self, ioc_value: str) -> Dict:
        """Make an exact-match lookup request to the Rosti /iocs endpoint.

        :param ioc_value: IOC value to look up
        """
        async with aiohttp.ClientSession() as session:
            headers = {"Accept": "application/json", "X-Api-Key": self.api_key}

            try:
                async with session.get(
                    urljoin(self.api_base_url, "iocs"),
                    params={"q": ioc_value},
                    headers=headers
                ) as response:
                    response.raise_for_status()
                    return await response.json()
            except aiohttp.ClientResponseError as e:
                return {"error": "HTTP error: {} {}".format(e.status, e.message)}
            except aiohttp.ClientError as e:
                return {"error": "Connection error: {}".format(str(e))}

    async def process_ioc(self, ioc_type: str, ioc_value: str) -> Dict:
        """Check an IOC against the Rosti threat intelligence database.

        :param ioc_type: Type of the IOC (must be in self.supported_iocs)
        :param ioc_value: IOC value to check
        """
        if ioc_type not in self.supported_iocs:
            return {"status": False, "error": f"Unsupported IOC type: {ioc_type}"}

        response = await self._make_request(ioc_value)

        if not response:
            return {"status": False}
        if "error" in response:
            return {"status": False, "error": response["error"]}

        ioc = response.get("data", [])[0] if response.get("data") else None

        if not ioc or response.get("data") is None:
            return {"status": False}

        return {
            "status": True,
            "category":     ioc.get("category", "N/A"),
            "date":         ioc.get("date", "N/A"),
            "timestamp":    ioc.get("timestamp", "N/A"), 
            "tags":         ioc.get("tags") or [],
            "comment":      ioc.get("comment", ""),
            "report_link":  urljoin(self.report_base_url, ioc.get("report", "")) if ioc.get("report", "") else "N/A",
        }