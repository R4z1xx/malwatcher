from pathlib import PurePosixPath
from urllib.parse import urljoin
import requests

class InQuest:
    """InQuest API class.\n
    Functions available :
        - check_dfi_hash() : Check hash in InQuest DFI
        - check_dfi_ioc() : Check IOC in InQuest DFI
        - check_iocdb() : Check IOC in InQuest IOCDB
        - check_repdb() : Check IOC in InQuest REPDB
    """
    def __init__(self, API_KEY):
        self.api_dfi_hash_url = "https://labs.inquest.net/api/dfi/search/hash/"
        self.api_dfi_ioc_url = "https://labs.inquest.net/api/dfi/search/ioc/"
        self.report_dfi_url = "https://labs.inquest.net/dfi/"
        self.api_iocdb_url = "https://labs.inquest.net/api/iocdb/search"
        self.report_iocdb_url = "https://labs.inquest.net/iocdb/search/"
        self.api_repdb_url = "https://labs.inquest.net/api/repdb/search"
        self.report_repdb_url = "https://labs.inquest.net/repdb/search/"
        self.api_key = API_KEY

    def _make_request(self, api_url, params):
        """Make request to InQuest API.
        """
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        try:
            response = requests.get(api_url, params=params, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            return None
        
    def check_dfi_hash(self, hash, type):
        """Check hash in InQuest DFI.
        :param hash: Hash
        :param type: Type of hash

        Retrieved ressources:
            - Classification
            - First seen date
            - Descriptions
            - MIME type
            - InQuest DFI link
        """
        if hash:
            dfi_response = self._make_request(urljoin(self.api_dfi_hash_url, type), params={"hash": hash})
            descriptions = []
            if dfi_response and dfi_response.get('data'):
                for alerts in dfi_response['data'][0].get('inquest_alerts', []):
                    descriptions.append(alerts.get('description', None))
                return {
                    'status': True,
                    'classification': dfi_response['data'][0]['classification'],
                    'first_seen': dfi_response['data'][0]['first_seen'],
                    'descriptions': descriptions,
                    'mime_type': dfi_response['data'][0]['mime_type'],
                    'inquest_url': urljoin(self.report_dfi_url, str(PurePosixPath('sha256', dfi_response['data'][0]['sha256'])))
                }
        return {'status': False}
    
    def check_dfi_ioc(self, ioc, type):
        """Check IOC in InQuest DFI.
        :param ioc: IOC
        :param type: Type of IOC

        Retrieved ressources:
            - Classification
            - First seen date
            - Descriptions
            - MIME type
            - InQuest DFI link
        """
        if ioc:
            if type in ['ipv4', 'ipv6']:
                type = 'ip'
            dfi_response = self._make_request(urljoin(self.api_dfi_ioc_url, type), params={"keyword": ioc})
            descriptions = []
            if dfi_response and dfi_response.get('data'):
                for alerts in dfi_response['data'][0].get('inquest_alerts', []):
                    descriptions.append(alerts.get('description', None))
                return {
                    'status': True,
                    'classification': dfi_response['data'][0]['classification'],
                    'first_seen': dfi_response['data'][0]['first_seen'],
                    'descriptions': descriptions,
                    'mime_type': dfi_response['data'][0]['mime_type'],
                    'inquest_url': urljoin(self.report_dfi_url, str(PurePosixPath('sha256', dfi_response['data'][0]['sha256'])))
                }
        return {'status': False}
    
    def check_iocdb(self, ioc):
        """Check IOC in InQuest IOCDB.
        :param ioc: IOC

        Retrieved ressources:
            - Number of times seen
            - First seen date
            - Last seen date
            - Description
            - InQuest IOCDB link
        """
        if ioc:
            iocdb_response = self._make_request(self.api_iocdb_url, params={"keyword": ioc})
            if iocdb_response and iocdb_response.get('data'):
                nb_found = len(iocdb_response['data'])
                return {
                    'status': True,
                    'nb_found': f"{nb_found}+" if nb_found == 1337 else nb_found,
                    'first_seen': iocdb_response['data'][0]['created_date'],
                    'last_seen': iocdb_response['data'][-1]['created_date'],
                    'description': iocdb_response['data'][0]['reference_text'],
                    'iocdb_url': urljoin(self.report_iocdb_url, ioc)
                }
        return {'status': False}
    
    def check_repdb(self, ioc):
        """Check IOC in InQuest REPDB.
        :param ioc: IOC

        Retrieved ressources:
            - Number of times found
            - First seen date
            - Last seen date
            - Reputation source
            - InQuest REPDB link
        """
        if ioc:
            repdb_response = self._make_request(self.api_repdb_url, params={"keyword": ioc})
            if repdb_response and repdb_response.get('data'):
                nb_found = len(repdb_response['data'])
                return {
                    'status': True,
                    'nb_found': f"{nb_found}+" if nb_found == 1337 else nb_found,
                    'first_seen': repdb_response['data'][0]['created_date'],
                    'last_seen': repdb_response['data'][-1]['created_date'],
                    'reputation_source': repdb_response['data'][0]['source'],
                    'repdb_url': urljoin(self.report_repdb_url, ioc)
                }
        return {'status': False}