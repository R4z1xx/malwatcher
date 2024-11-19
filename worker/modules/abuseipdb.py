from urllib.parse import urljoin, quote_plus
import requests

class AbuseIPDB:
    """AbuseIPDB API class.\n
    Functions available :
        - check_ip() : Check IP in AbuseIPDB
    """
    def __init__(self, API_KEY):
        self.report_url = "https://www.abuseipdb.com/check/"
        self.api_base_url = "https://api.abuseipdb.com/api/v2/check"
        self.api_key = API_KEY

    def _make_request(self, ip_address):
        """Make request to AbuseIPDB API.
        """
        headers = {"Accept": "application/json", "Key": self.api_key}
        params = {"ipAddress": ip_address}
        try:
            response = requests.get(self.api_base_url, params=params, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            return None

    def check_ip(self, ip_address):
        """Check IP in AbuseIPDB.
        :param ip_address: IP

        Retrieved ressources:
            - AbuseIPDB score
            - AbuseIPDB link
        """
        if self.api_key and ip_address:
            ip_response = self._make_request(ip_address)
            if ip_response:
                return {
                    'status': True,
                    'score': ip_response['data'].get('abuseConfidenceScore', None),
                    'country': ip_response['data'].get('countryCode', None),
                    'as_owner': ip_response['data'].get('isp', None),
                    'report_count': len(ip_response['data'].get('reports', [])),
                    'abuseipdb_link': urljoin(self.report_url, quote_plus(ip_address))
                }
        return {'status': False}