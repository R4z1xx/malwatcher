from pathlib import PurePosixPath
from urllib.parse import urljoin
import requests

class VirusTotal:
    """VirusTotal API class.\n
    Functions available :
        - check_ip() : Check IP in VT
        - check_domain() : Check domain in VT
        - check_url() : Check URL in VT
        - check_file() : Check hash in VT
    """
    def __init__(self, API_KEY, ENTERPRISE):
        self.report_url = "https://www.virustotal.com/gui/"
        self.api_base_url = "https://www.virustotal.com/api/v3/"
        self.api_key = API_KEY
        self.enterprise = ENTERPRISE

    def _make_request(self, endpoint):
        """Make request to VT API.
        """
        headers = {"accept": "application/json", "x-apikey": self.api_key}
        try:
            response = requests.get(urljoin(self.api_base_url, endpoint), headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            return None

    def _get_score(self, vt_response):
        """
        Get VT score from response.
        """
        malicious_count = vt_response['data']['attributes']['last_analysis_stats'].get('malicious', 0)
        total_count = sum(vt_response['data']['attributes']['last_analysis_stats'].values(), 0)
        return f'{malicious_count}/{total_count}' if total_count else '0/0'

    def check_ip(self, ip_address):
        """Check IP in VT.
        :param ip_address: IP

        Retrieved ressources:
            - VT score
            - AS Owner
            - Country code
            - VT link
        """
        if self.api_key and ip_address:
            ip_response = self._make_request(str(PurePosixPath('ip_addresses', ip_address)))
            ip_score = self._get_score(ip_response) if ip_response else None
            if ip_score:
                return {
                    'status': True, 
                    'vt_score': ip_score, 
                    'as_owner': ip_response['data']['attributes'].get('as_owner', None), 
                    'country': ip_response['data']['attributes'].get('country', None), 
                    'vt_link': urljoin(self.report_url, str(PurePosixPath('ip-address', ip_address)))
                }
        return {'status': False}

    def check_domain(self, domain):
        """Check domain in VT.
        :param domain: Domain

        Retrieved ressources:
            - VT score
            - Crowdsourced Context
            - VT link
        """
        if self.api_key and domain:
            domain_response = self._make_request(str(PurePosixPath('domains', domain)))
            domain_score = self._get_score(domain_response) if domain_response else None
            if domain_score:
                return {
                    'status': True, 
                    'vt_score': domain_score, 
                    'crowdsourced_context': domain_response['data']['attributes'].get('crowdsourced_context', [{}])[0].get('details', None),
                    'vt_link': urljoin(self.report_url, str(PurePosixPath('domain', domain)))
                }
        return {'status': False}

    def check_url(self, url_hash):
        """Check URL in VT.
        :param url_hash: URL hash

        Retrieved ressources:
            - VT score
            - Crowdsourced Context
            - VT link
        """
        if self.api_key and url_hash:
            url_response = self._make_request(str(PurePosixPath('urls', url_hash)))
            if url_response and 'data' in url_response:
                url_score = self._get_score(url_response)
                return {
                    'status': True, 
                    'vt_score': url_score, 
                    'crowdsourced_context': url_response['data']['attributes'].get('crowdsourced_context', [{}])[0].get('details', None), # BUGGED
                    'vt_link': urljoin(self.report_url, str(PurePosixPath('url', url_hash)))
                }
        return {'status': False}
    
    def check_file(self, file_hash):
        """Check file in VT.
        :param file_hash: File hash

        Retrieved ressources:
            - VT score
            - Popular Threat Classification
            - VT link
        """
        if self.api_key and file_hash:
            file_response = self._make_request(str(PurePosixPath('files', file_hash)))
            if file_response and 'data' in file_response:
                file_score = self._get_score(file_response)
                return {
                    'status': True, 
                    'vt_score': file_score, 
                    'popular_threat_classification': file_response['data']['attributes'].get('popular_threat_classification', {}).get('suggested_threat_label', None), 
                    'vt_link': urljoin(self.report_url, str(PurePosixPath('file', file_hash)))
                }
        return {'status': False}