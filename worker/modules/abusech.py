from urllib.parse import urljoin
import requests

class Bazaar:
    """Bazaar API class.\n
    Functions available : 
        - check_hash() : Check hash in Bazaar
    """
    def __init__(self):
        self.root_url = 'https://mb-api.abuse.ch/api/v1/'
        self.error_tag = ['hash_not_found', 'http_post_expected', 'illegal_hash', 'no_hash_provided']

    def _make_request(self, data):
        """Make request to Bazaar API.
        """
        headers = {"accept": "application/json"}
        try:
            response = requests.post(self.root_url, headers=headers, data=data)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            return None

    def check_hash(self, hash):
        """Check hash in Bazaar.
        :param hash: md5, sha1 or sha256
        
        Retrieved ressources:
            - Number of times the hash has been seen
            - First seen
            - Last seen
            - File MIME type
            - Malware Family
            - Tags
            - Bazaar link
        """
        if hash:
            response = self._make_request({"query": "get_info", "hash": hash})
            if response and response.get('query_status', None) not in self.error_tag:
                return {
                    'status': True, 
                    'seen_count': len(response['data']),
                    'first_seen': response.get('data', [{}])[0].get('first_seen', None),
                    'last_seen': response.get('data', [{}])[0].get('last_seen', None),
                    'file_type': response.get('data', [{}])[0].get('file_type_mime', None),
                    'signature': response.get('data', [{}])[0].get('signature', None),
                    'tags': response.get('data', [{}])[0].get('tags', None),
                    'bazaar_link': urljoin("https://bazaar.abuse.ch/sample/", response.get('data', [{}])[0].get('sha256_hash', None))
                }
        return {'status': False}

class ThreatFox:
    """ThreatFox API class.\n
    Functions available :
        - check_ioc() : Check IP, domain, URL, md5, sha256 in ThreatFox
    """
    def __init__(self):
        self.root_url = 'https://threatfox-api.abuse.ch/api/v1/'
        self.error_tag = ['no_result']

    def _make_request(self, data):
        """Make request to ThreatFox API.
        """
        headers = {"accept": "application/json"}
        try:
            response = requests.post(self.root_url, headers=headers, json=data)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            return None
        
    def check_ioc(self, ioc, type):
        """Check IP, domain, URL, md5, sha256 in ThreatFox.
        :param ioc: IP, domain, URL, md5, sha256
        :param type: ip, domain, url, hash

        Retrieved ressources:
            - Number of IOCs found
            - First seen
            - Last seen
            - Threat type
            - Threat description
            - ThreatFox link
        """
        if ioc:
            if type not in ['md5', 'sha256']:
                response = self._make_request({"query": "search_ioc", "search_term": ioc})
            else:
                response = self._make_request({"query": "search_hash", "hash": ioc})
            if response and response.get('query_status', None) not in self.error_tag:
                return {
                    'status': True,
                    'ioc_count': len(response['data']),
                    'first_seen': response.get('data', [{}])[0].get('first_seen', None),
                    'last_seen': response.get('data', [{}])[0].get('last_seen', None),
                    'malware_alias': response.get('data', [{}])[0].get('malware_alias', None),
                    'threat_desc': response.get('data', [{}])[0].get('threat_type_desc', None),
                    'threatfox_link': urljoin("https://threatfox.abuse.ch/ioc/", response.get('data', [{}])[0].get('id', None))
                }
        return {'status': False}

class Urlhaus:
    """URLhaus API class.\n
    Functions available :
        - check_url() : Check URL in URLhaus
        - check_domain_ip() : Check domain or IP in URLhaus
        - check_hash() : Check md5 or sha256 hash in URLhaus
    """
    def __init__(self):
        self.root_url = 'https://urlhaus-api.abuse.ch/v1/'
        self.error_tag = ['no_results', 'http_post_expected', 'invalid_url', 'invalid_host', 'invalid_sha256', 'invalid_md5']
    
    def _make_request(self, endpoint, data):
        """Make request to URLhaus API.
        """
        headers = {"accept": "application/json"}
        try:
            response = requests.post(urljoin(self.root_url, endpoint), headers=headers, data=data)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            return None

    def check_url(self, url):
        """Check URL in URLhaus.
        :param url: URL

        Retrieved ressources: 
            - URL status
            - Last online (if offline)
            - Threat
            - Tags
            - Payloads (Yes/No)
            - URLHaus link
        """
        if url:
            url_response = self._make_request('url', {"url": url})
            if url_response and url_response.get('query_status', None) not in self.error_tag:
                return {
                    'status': True, 
                    'url_status': url_response.get('url_status', None),
                    'last_online': url_response.get("last_online", None) if url_response.get('url_status', None) == "offline" else None,
                    'threat': url_response.get('threat', None),
                    'tags': url_response.get('tags', None), 
                    'payloads': 'Yes' if url_response.get('payloads', None) else 'No',
                    'urlhaus_link': url_response.get('urlhaus_reference', None)
                }
        return {'status': False}
    
    def check_domain_ip(self, ioc):
        """Check domain or IP in URLhaus.
        :param ioc: domain or IP

        Retrieved ressources:
            - Number of URLs observed on this host
            - Blacklist (Spamhaus DBL)
            - URLhaus link
        """
        if ioc:
            response = self._make_request('host', {"host": ioc})
            if response and response.get('query_status', None) not in self.error_tag:
                return {
                    'status': True, 
                    'url_count': response.get('url_count', None), # Number of URLs observed on this host
                    'blacklist': response.get('blacklist', {}).get('spamhaus_dbl', None),
                    'urlhaus_link': response['urlhaus_reference']
                }
        return {'status': False}
    
    def check_hash(self, hash, type):
        """Check hash in URLhaus.
        :param hash: md5, sha256
        :param type: "md5", "sha256"

        Retrieved ressources:
            - Malware Family
            - File type
            - First seen
            - Last seen
            - Number of URLs observed with this hash
            - URLhaus link
        """
        if hash:
            response = self._make_request('payload', {type + '_hash': hash})
            if response and response.get('query_status', None) not in self.error_tag:
                return {
                    'status': True, 
                    'signature': response.get('signature', None), # Malware Family
                    'file_type': response.get('file_type', None),
                    'first_seen': response.get('firstseen', None),
                    'last_seen': response.get('lastseen', None),
                    'url_count': response.get('url_count', None),
                    'urlhaus_link': response.get('urlhaus_reference', None)
                }
        return {'status': False}