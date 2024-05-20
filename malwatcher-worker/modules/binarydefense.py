import requests

class BinaryDefense:
    """Binary Defense banlist class.\n
    Functions available :
        - check_ip() : Check IP in Binary Defense banlist
    """

    def __init__(self):
        self.root_url = 'https://www.binarydefense.com/banlist.txt'

    def _make_request(self):
        """Make request to Binary Defense banlist.
        """
        headers = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'}
        try:
            response = requests.get(self.root_url, headers=headers)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            return None

    def check_ip(self, ip):
        """Check IP in Binary Defense banlist.
        :param ip: IP
        """
        if ip:
            response = self._make_request()
            if response and ip in response:
                return {'status': True}
        return {'status': False}