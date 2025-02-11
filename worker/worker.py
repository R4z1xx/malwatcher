from modules import abusech, abuseipdb, alienvault, binarydefense, digitalside, ipsum, virustotal, polyswarm, triage, inquest
from concurrent.futures import ProcessPoolExecutor, as_completed
from tools import defang, ioc_parser
from aiohttp import web
import logging
import toml
import sys

class Worker:
    """Worker class for checking IOCs in defined modules.
    Functions available :
        - check_ioc() : Check IOC in defined modules using threads
    """
    def __init__(self, logger, config):
        self.logger = logger
        self.config = config
        self.defanger = defang.Defanger()
        self.parser = ioc_parser.IOCParser()
        self._load_modules()

    def _load_modules(self):
        """Load and initialize modules.
        """
        self.vt = virustotal.VirusTotal(self.config["modules"]["virustotal-api"]["vt-key"])
        self.abuseipdb = abuseipdb.AbuseIPDB(self.config["modules"]["abuseipdb-api"]["abuseipdb-key"])
        self.alienvault = alienvault.AlienVault(self.config["modules"]["otx-api"]["otx-key"])
        self.polyswarm = polyswarm.PolySwarm(self.config["modules"]["polyswarm-api"]["polyswarm-key"])
        self.triage = triage.Triage(self.config["modules"]["triage-api"]["triage-key"])
        self.inquest = inquest.InQuest(self.config["modules"]["inquest-api"]["inquest-key"])
        self.abusech_bazaar = abusech.Bazaar()
        self.abusech_threatfox = abusech.ThreatFox()
        self.abusech_urlhaus = abusech.Urlhaus()
        self.binarydefense = binarydefense.BinaryDefense()
        self.digitalside = digitalside.DigitalSide()
        self.ipsum = ipsum.IPSum()

    def _define_ioc_type(self, ioc):
        """Define type of IOC.
        """
        if ioc:
            return self.parser.parse(ioc)
        return None

    def _vt_url_hash(self, ioc):
        """Calculate sha256 hash of URL for VT.
        """
        if ioc:
            return self.parser.url_hash(ioc)
        return None

    def _execute_check(self, func, *args):
        """Execute check function.
        """
        try:
            self.logger.debug(f"Executing {func} with {args}")
            return func(*args)
        except Exception as e:
            self.logger.error(f"Error in {func}: {e}")
            return None

    async def limit_json_keys(self, request):
        """Limit JSON keys to only one.
        """
        if request.headers.get('Content-Type') == 'application/json' and request.body_exists:
            json_data = await request.json()
        else:
            self.logger.info("Request does not contain JSON data.")
            raise web.HTTPBadRequest(
                reason="Invalid request: Request does not contain JSON data.",
                headers={'Content-Type': 'application/json'}
            )

        if len(json_data.keys()) > 1:
            self.logger.info("More than one key-value pair found.")
            raise web.HTTPBadRequest(
                reason="Invalid request: More than one key-value pair found.",
                headers={'Content-Type': 'application/json'}
            )
        self.logger.debug("One key-value pair found.")
        return

    async def check_ioc(self, request):
        """Check IOC in defined modules using threads.
        """
        await self.limit_json_keys(request)
        ioc = await request.json()
        ioc = ioc.get("ioc")
        results = {}
        if ioc:
            type = self._define_ioc_type(ioc)
            self.logger.info(f"IOC type defined : {type}")
            match type:
                case "ipv4":
                    check_modules = [
                        ["virustotal", self.vt.check_ip, ioc],
                        ["alienvault", self.alienvault.check_ioc, ioc, type],
                        ["digitalside", self.digitalside.check_ioc, ioc, type],
                        ["urlhaus", self.abusech_urlhaus.check_domain_ip, ioc],
                        ["threatfox", self.abusech_threatfox.check_ioc, ioc, type],
                        ["abuseipdb", self.abuseipdb.check_ip, ioc],
                        ["binarydefense", self.binarydefense.check_ip, ioc],
                        ["ipsum", self.ipsum.check_ip, ioc],
                        ["triage", self.triage.search_ioc, ioc, type],
                        ["inquest-iocdb", self.inquest.check_iocdb, ioc],
                        ["inquest-repdb", self.inquest.check_repdb, ioc],
                        ["inquest-dfi-ioc", self.inquest.check_dfi_ioc, ioc, type],
                    ]
                case "ipv6":
                    check_modules = [
                        ["virustotal", self.vt.check_ip, ioc],
                        ["alienvault", self.alienvault.check_ioc, ioc, type],
                        ["urlhaus", self.abusech_urlhaus.check_domain_ip, ioc],
                        ["threatfox", self.abusech_threatfox.check_ioc, ioc, type],
                        ["abuseipdb", self.abuseipdb.check_ip, ioc],
                        ["binarydefense", self.binarydefense.check_ip, ioc],
                        ["ipsum", self.ipsum.check_ip, ioc],
                        ["inquest-iocdb", self.inquest.check_iocdb, ioc],
                        ["inquest-repdb", self.inquest.check_repdb, ioc],
                        ["inquest-dfi-ioc", self.inquest.check_dfi_ioc, ioc, type],
                    ]
                case "domain":
                    check_modules = [
                        ["virustotal", self.vt.check_domain, ioc],
                        ["alienvault", self.alienvault.check_ioc, ioc, type],
                        ["digitalside", self.digitalside.check_ioc, ioc, type],
                        ["urlhaus", self.abusech_urlhaus.check_domain_ip, ioc],
                        ["threatfox", self.abusech_threatfox.check_ioc, ioc, type],
                        ["triage", self.triage.search_ioc, ioc, type],
                        ["inquest-iocdb", self.inquest.check_iocdb, ioc],
                        ["inquest-repdb", self.inquest.check_repdb, ioc],
                        ["inquest-dfi-ioc", self.inquest.check_dfi_ioc, ioc, type],
                    ]
                case "url":
                    check_modules = [
                        ["virustotal", self.vt.check_url, self._vt_url_hash(ioc)],
                        ["alienvault", self.alienvault.check_ioc, ioc, type],
                        ["digitalside", self.digitalside.check_ioc, ioc, type],
                        ["urlhaus", self.abusech_urlhaus.check_url, ioc],
                        ["threatfox", self.abusech_threatfox.check_ioc, ioc, type],
                        ["polyswarm", self.polyswarm.search_url, ioc],
                        ["inquest-iocdb", self.inquest.check_iocdb, ioc],
                        ["inquest-repdb", self.inquest.check_repdb, ioc],
                        ["inquest-dfi-ioc", self.inquest.check_dfi_ioc, ioc, type],
                    ]
                case "md5":
                    check_modules = [
                        ["virustotal", self.vt.check_file, ioc],
                        ["alienvault", self.alienvault.check_ioc, ioc, type],
                        ["digitalside", self.digitalside.check_ioc, ioc, type],
                        ["urlhaus", self.abusech_urlhaus.check_hash, ioc, type],
                        ["threatfox", self.abusech_threatfox.check_ioc, ioc, type],
                        ["bazaar", self.abusech_bazaar.check_hash, ioc],
                        ["triage", self.triage.search_ioc, ioc, type],
                        ["polyswarm", self.polyswarm.search_hash, ioc, type],
                        ["inquest-iocdb", self.inquest.check_iocdb, ioc],
                        ["inquest-repdb", self.inquest.check_repdb, ioc],
                        ["inquest-dfi-hash", self.inquest.check_dfi_hash, ioc, type],
                    ]
                case "sha1":
                    check_modules = [
                        ["virustotal", self.vt.check_file, ioc],
                        ["alienvault", self.alienvault.check_ioc, ioc, type],
                        ["digitalside", self.digitalside.check_ioc, ioc, type],
                        ["bazaar", self.abusech_bazaar.check_hash, ioc],
                        ["triage", self.triage.search_ioc, ioc, type],
                        ["polyswarm", self.polyswarm.search_hash, ioc, type],
                        ["inquest-iocdb", self.inquest.check_iocdb, ioc],
                        ["inquest-repdb", self.inquest.check_repdb, ioc],
                        ["inquest-dfi-hash", self.inquest.check_dfi_hash, ioc, type],
                    ]
                case "sha256":
                    check_modules = [
                        ["virustotal", self.vt.check_file, ioc],
                        ["alienvault", self.alienvault.check_ioc, ioc, type],
                        ["digitalside", self.digitalside.check_ioc, ioc, type],
                        ["urlhaus", self.abusech_urlhaus.check_hash, ioc, type],
                        ["threatfox", self.abusech_threatfox.check_ioc, ioc, type],
                        ["bazaar", self.abusech_bazaar.check_hash, ioc],
                        ["triage", self.triage.search_ioc, ioc, type],
                        ["polyswarm", self.polyswarm.search_hash, ioc, type],
                        ["inquest-iocdb", self.inquest.check_iocdb, ioc],
                        ["inquest-repdb", self.inquest.check_repdb, ioc],
                        ["inquest-dfi-hash", self.inquest.check_dfi_hash, ioc, type],
                    ]
                case _:
                    self.logger.error(f'IOC type "{type}" not supported.')
                    results["error"] = f'IOC type "{type}" not supported.'
                    return web.json_response(results)
            self.logger.info("Starting threads for modules checks.")
            with ProcessPoolExecutor(max_workers=len(check_modules)) as executor:
                futures = {executor.submit(self._execute_check, func, *args): ((func, *args), module_name) for module_name, func, *args in check_modules}
                for future in as_completed(futures):
                    result = future.result()
                    module = futures[future][1]
                    if result is not None:
                        results[module] = result
            self.logger.info("Threads finished.")
            results = dict(sorted(results.items(), key=lambda x: x[1].get("status", False), reverse=True))
            ioc_defang = self.defanger.defang(ioc)
            results["ioc"] = ioc_defang
            results["type"] = type.upper()
        else:
            self.logger.error("No IOC provided.")
            results["error"] = "No IOC provided."
        return web.json_response(results)

def setup_logger(config):
    """Setup logger.
    """
    try:
        logger = logging.getLogger(__name__)
        logger.setLevel(getattr(logging, config["logging"]["log-level"].upper(), None))
        handler = logging.FileHandler(config["logging"]["log-file"])
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] {"WORKER"} %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    except Exception as e:
        with open(config["logging"]["log-file"], "a") as file:
            file.write(f"[CRITICAL] Error while setting up logging: {e}\n")
        sys.exit(1)
    return logger

if __name__ == "__main__":
    try:
        config = toml.load("/worker/config/config.toml")
    except Exception as e:
        with open("/worker/logs/malwatcher.log", "a") as file:
            file.write(f"[CRITICAL] Error while loading config: {e}\n")
        sys.exit(1)
    logger = setup_logger(config)
    worker = Worker(logger, config)
    worker_api = web.Application()
    worker_api.router.add_post("/check", worker.check_ioc)
    web.run_app(worker_api)
