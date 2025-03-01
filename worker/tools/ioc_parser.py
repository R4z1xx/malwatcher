import hashlib
import re

class IOCParser:
    def __init__(self):
        self.patterns = [
            {"find": r"^(?:\d{1,3}\.){3}\d{1,3}$", "type": "ipv4"},
            # {"find": r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}", "type": "ipv6"}, # Simple one
            {"find": r"^(([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,6}:|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|([0-9a-fA-F]{1,4}:)(:[0-9a-fA-F]{1,4}){1,6}|:((:[0-9a-fA-F]{1,4}){1,7}|:))$", "type": "ipv6"}, # Any IPv6 format
            {"find": r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}$", "type": "domain"},
            {"find": r"^[a-fA-F0-9]{64}$", "type": "sha256"},
            {"find": r"^[a-fA-F0-9]{40}$", "type": "sha1"},
            {"find": r"^[a-fA-F0-9]{32}$", "type": "md5"},
            {"find": r"^(?:https?://)(?:[a-z0-9-]+\.)[a-z0-9.-]+(?::\d+)?(?:/[^\s]*)?$", "type": "url"},
        ]
        self.ioc_patterns = [{"find": re.compile(i["find"], re.VERBOSE), "type": i["type"]} for i in self.patterns]

    def parse(self, ioc):
        """Parse IOC and return its type.
        :param ioc: IOC to parse
        
        Returned type can be :
            - ipv4
            - ipv6
            - domain
            - url
            - sha256
            - sha1
            - md5
        """
        ioc_type = None
        for pattern in self.ioc_patterns:
            if pattern["find"].match(ioc):
                ioc_type = pattern["type"]
                break
        return ioc_type
    
    def url_hash(self, url):
        """Calculate sha256 hash of URL.
        :param url: URL to hash
        """
        return hashlib.sha256(url.encode()).hexdigest()