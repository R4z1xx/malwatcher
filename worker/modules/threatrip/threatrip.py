from modules.base import BasePlugin
import os

from typing import Dict
from urllib.parse import urljoin
import aiohttp

class ThreatRip(BasePlugin):
    def __init__(self):
        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        super().__init__(config_path)
        self.report_base_url = "https://www.threat.rip/file/"
        self.api_base_url = "https://www.threat.rip/api/reports/file/"

    async def _make_request(self, ioc_value: str) -> Dict:
        """Make an exact-match lookup request to the ThreatRip /iocs endpoint.

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
        """Check an IOC against the ThreatRip threat intelligence database.

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

        ioc = response if response else None

        if not ioc or response.get("report") is None:
            return {"status": False}

        return {
            "status": True,
            "threat_score": ioc.get("report", {}).get("threat_score", 0),
            "threatName": ioc.get("report", {}).get("threatName", "N/A"),
            "verdict": ioc.get("report", {}).get("verdict", "N/A"),
            "tags": [item['tag'] for item in ioc.get("tags", [])][:5] if ioc.get("tags") is not None else "N/A",
            "report_link": urljoin(self.report_base_url, ioc.get("reportId", "")) if ioc.get("reportId", "") else "N/A",
        }