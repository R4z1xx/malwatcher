from urllib.parse import urljoin
import requests

class Triage:
    """Triage API class.\n
    Functions available :
        - search_ioc() : Check IOC in Triage
    """
    def __init__(self, API_KEY):
        self.report_url = "https://tria.ge/"
        self.api_base_url = "https://tria.ge/api/v0/search"
        self.api_key = API_KEY

    def _make_request(self, endpoint):
        """Make request to Triage API.
        """
        headers = {"Authorization": f"Bearer {self.api_key}"}
        try:
            response = requests.get(urljoin(self.api_base_url, endpoint), headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            return None
        
    def search_ioc(self, ioc, type):
        """Search IOC in Triage.
        :param ioc: IOC
        :param type: Type of IOC

        Retrieved ressources:
            - Related filename
            - Related URL
            - Submission date
            - Triage link
        """
        if self.api_key and ioc:
            if type in ['ipv4', 'ipv6']:
                type = 'ip'
            triage_response = self._make_request(f"?query={type}:{ioc}")
            if triage_response and triage_response.get('data', None):
                return {
                    'status': True,
                    'related_filename': triage_response['data'][0].get('filename', None),
                    'related_url': triage_response['data'][0].get('url', None),
                    'submitted': triage_response['data'][0].get('submitted', None),
                    'triage_link': urljoin(self.report_url, triage_response['data'][0].get('id', None))
                }
        return {'status': False}