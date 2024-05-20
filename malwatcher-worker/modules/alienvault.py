from OTXv2 import OTXv2, IndicatorTypes
from pathlib import PurePosixPath
from urllib.parse import urljoin, quote_plus

class AlienVault:
    """AlienVault OTX API class.\n
    Functions available :
        - check_ioc() : Check IP, domain, URL, md5, sha1, sha256 in AlienVault OTX
    """
    def __init__(self, API_KEY):
        self.report_url = 'https://otx.alienvault.com/indicator/'
        self.api_base_url = 'https://otx.alienvault.com/'
        self.api_key = API_KEY
        self.otx = OTXv2(self.api_key, server=self.api_base_url)
        self.otx_ioc_types = {
            'ipv4': IndicatorTypes.IPv4,
            'ipv6': IndicatorTypes.IPv6,
            'domain': IndicatorTypes.DOMAIN,
            'url': IndicatorTypes.URL,
            'md5': IndicatorTypes.FILE_HASH_MD5,
            'sha1': IndicatorTypes.FILE_HASH_SHA1,
            'sha256': IndicatorTypes.FILE_HASH_SHA256
        }   

    def _make_request(self, type, ioc):
        """Make request to AlienVault OTX API.
        """
        return self.otx.get_indicator_details_by_section(type, ioc, 'general')

    def check_ioc(self, ioc, type):
        """Check IOC in AlienVault OTX.
        :param ioc: IOC to check
        :param type: Type of IOC

        Retrieved ressources:
            - Number of pulses the IOC is in
            - OTX link
        """
        if ioc:
            response = self._make_request(self.otx_ioc_types[type], ioc)
            if response:
                return {
                    'status': True,
                    'pulses_count': response.get('pulse_info', {}).get('count', '0'),
                    'as_owner': response.get('asn', None),
                    'country': response.get('country_name', None),
                    'otx_link': urljoin(self.report_url, str(PurePosixPath(type if type not in ['ipv4', 'ipv6'] else 'ip', quote_plus(ioc, safe=':'))))
                }
        return {'status': False}