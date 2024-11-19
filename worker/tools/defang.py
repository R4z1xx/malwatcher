import re

class Defanger:
    def __init__(self):
        self.patterns = [
            {"find": "http:", "replace": "hxxp:"},
            {"find": "https:", "replace": "hxxps:"},
            {"find": r":\/\/", "replace": "[://]"},
            {"find": r"(?<=\w)(\.)(?=\w)", "replace": "[.]"},
            {"find": r"(?<=\S)(@)(?=\S)", "replace": "(at)"},
        ]
        self.defang_patterns = [{"find": re.compile(i["find"], re.VERBOSE), "replace": i["replace"]} for i in self.patterns]

    def defang(self, ioc):
        """Defang url, domain, ip, email.
        :param ioc: IOC to defang
        """
        defanged_ioc = ioc
        for pattern in self.defang_patterns:
            defanged_ioc = pattern["find"].sub(pattern["replace"], defanged_ioc)
        return defanged_ioc
