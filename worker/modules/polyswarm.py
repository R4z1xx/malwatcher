from urllib.parse import urljoin
import requests

class PolySwarm:
    """PolySwarm API class.\n
    Functions available :
        - search_url() : Search URL in PolySwarm
        - search_hash() : Search hash in PolySwarm
    """
    def __init__(self, API_KEY):
        self.api_url_base_url = "https://api.polyswarm.network/v3/search/url"
        self.api_hash_base_url = "https://api.polyswarm.network/v3/search/hash/"
        self.api_key = API_KEY

    def _make_request(self, api_url, params):
        """Make request to PolySwarm API.
        """
        headers = {"Authorization": self.api_key}
        try:
            response = requests.get(api_url, params=params, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            return None

    def search_url(self, url):
        """Search URL in PolySwarm.\n
        :param url: URL

        Retrieved ressources:
            - PolySwarm score
            - First seen
            - Last seen
            - Last scanned
            - Detections scores
            - PolySwarm link
        """
        if self.api_key and url:
            params = {
                "url": url, 
                "community": "default"
            }
            polyswarm_response = self._make_request(self.api_url_base_url, params)
            if polyswarm_response and polyswarm_response.get('result', None):
                score = int(polyswarm_response['result'][0]['polyscore'] * 100)
                return {
                    'status': True,
                    'score': f'{score}%',
                    'first_seen': polyswarm_response['result'][0]['first_seen'],
                    'last_seen': polyswarm_response['result'][0]['last_seen'],
                    'last_scanned': polyswarm_response['result'][0]['last_scanned'],
                    'detections': polyswarm_response['result'][0]['detections'], # Contains : Benign, Malicious, Total
                    'polyswarm_link': polyswarm_response['result'][0]['permalink']
                }
        return {'status': False}

    def search_hash(self, hash, type):
        """Search hash in PolySwarm.\n
        :param hash: Hash
        :param type: Type of hash (md5, sha1, sha256)
        
        Retrieved ressources:
            - PolySwarm score
            - Extended type
            - MIME type
            - First seen
            - Last seen
            - Last scanned
            - Detections
            - PolySwarm link
        """
        if self.api_key and hash:
            params = {
                "hash": hash, 
                "community": "default"
            }
            polyswarm_response = self._make_request(urljoin(self.api_hash_base_url, type), params)
            if polyswarm_response.get('result', None):
                score = int(polyswarm_response['result'][0]['polyscore'] * 100)
                return {
                    'status': True,
                    'score': f'{score}%',
                    'extended_type': polyswarm_response['result'][0]['extended_type'],
                    'mime_type': polyswarm_response['result'][0]['mimetype'],
                    'first_seen': polyswarm_response['result'][0]['first_seen'],
                    'last_seen': polyswarm_response['result'][0]['last_seen'],
                    'last_scanned': polyswarm_response['result'][0]['last_scanned'],
                    'detections': polyswarm_response['result'][0]['detections'], # Contains : Benign, Malicious, Total
                    'polyswarm_link': polyswarm_response['result'][0]['permalink']
                }
        return {'status': False}