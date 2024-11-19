from apiosintDS import apiosintDS

class DigitalSide:
    """DigitalSide API class.\n
    Functions available :
        - check_ioc() : Check IP, domain, URL, md5, sha1, sha256 in DigitalSide
    """

    def __init__(self):
        self.typeDS = {
            'ipv4': 'ip',
            'domain': 'domain',
            'url': 'url',
            'md5': 'hash',
            'sha1': 'hash',
            'sha256': 'hash'
        }

    def _make_request(self, ioc):
        """Make request to DigitalSide API.
        """
        try:
            return apiosintDS.request(entities=[ioc])
        except ValueError as e:
            print(f"Request failed: {e}")
            return None
    
    def check_ioc(self, ioc, type):
        """Check IP in DigitalSide.
        :param ioc: IP
        :param type: Type of IOC

        Retrieved ressources:
            - DigitalSide link
        """
        if ioc:
            response = self._make_request(ioc)
            if response and response.get('generalstatistics', {}).get('itemsFound', 0) > 0:
                return {
                    'status': True,
                    'ds_link': response.get(self.typeDS[type], {}).get('items', [{}])[0].get('online_reports', {}).get('OSINTDS_REPORT', None)
                }
        return {'status': False}