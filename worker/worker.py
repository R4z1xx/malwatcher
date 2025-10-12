from typing import List, Dict, Optional
import importlib.util, logging, yaml, sys, os, asyncio, functools
from pathlib import Path
from aiohttp import web

from modules.base import BasePlugin
from utils import defang, ioc_parser

class ModuleLoader:
    def __init__(self) -> None:
        self.modules_dir = Path(__file__).parent / "modules"
    
    def load_modules(self) -> List:
        '''Load all modules from the modules directory

        :return: List of loaded modules
        '''
        modules = []
        for module_dir in self.modules_dir.iterdir():
            if module_dir.is_dir():
                modules += self._load_module(module_dir)
        return modules
    
    def _load_module(self, module_dir: Path) -> List:
        '''Load a single module from a directory

        :param module_dir: Path to the module directory

        :return: List of loaded modules
        '''
        module_modules = []
        module_name = module_dir.name
        module_file = module_dir / f"{module_name}.py"
        
        if not module_file.exists():
            return module_modules
            
        try:
            spec = importlib.util.spec_from_file_location(
                f"modules.{module_name}", 
                module_file
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            for attr in dir(module):
                cls = getattr(module, attr)
                if self._is_valid_plugin_class(cls):
                    logger.debug(f"Loading module {module_name}")
                    plugin = cls()
                    if plugin.is_enabled():
                        module_modules.append(plugin)
        
        except Exception as e:
            logger.error(f"Error loading module {module_name}: {str(e)}")
        
        return module_modules
    
    def _is_valid_plugin_class(self, cls: type) -> bool:
        '''Check if a class is a valid plugin class

        :param cls: Class to check
        '''
        return (
            isinstance(cls, type) and
            issubclass(cls, BasePlugin) and
            cls != BasePlugin
        )

class Worker:
    '''Worker class for checking IOCs in defined modules

    Functions available :
    - check_ioc() : Check IOC in defined modules using threads
    '''
    def __init__(self, logger: logging.Logger, config: Dict, modules: List) -> None:
        self.modules = modules
        self.logger = logger
        self.config = config
        self.defanger = defang.Defanger()
        self.parser = ioc_parser.IOCParser()

    def _define_ioc_type(self, ioc: str) -> Optional[str]:
        '''Define type of IOC
        '''
        if ioc:
            return self.parser.parse(ioc)
        return None

    async def _limit_json_keys(self, request: web.Request) -> None:
        '''Limit JSON keys to only one
        '''
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
    
    async def _create_async_task(self, module_name, func, *args):
        '''Create async task with proper error handling and per-module timeout'''
        try:
            logger.debug(f"Processing {module_name} for {args}")
            if asyncio.iscoroutinefunction(func):
                result = await asyncio.wait_for(func(*args), timeout=self.config["worker"]["timeout"])
            else:
                loop = asyncio.get_event_loop()
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, functools.partial(func, *args)),
                    timeout=self.config["worker"]["timeout"]
                )
            logger.debug(f"Finished processing {module_name} with result {result}")
            return (module_name, result)
        except Exception as e:
            self.logger.error(f"Error in {module_name}: {str(e)}")
            return (module_name, e)

    async def check_ioc(self, request: web.Request) -> web.Response:
        '''Check IOC in defined modules using asyncio with per-module timeouts'''
        await self._limit_json_keys(request)
        ioc = await request.json()
        ioc = ioc.get("ioc").lower()
        results = {}
        
        if not ioc:
            self.logger.error("No IOC provided.")
            results["error"] = "No IOC provided."
            return web.json_response(results)

        ioc_type = self._define_ioc_type(ioc)
        self.logger.debug(f"IOC type defined : {ioc_type}")
        if not ioc_type:
            self.logger.error(f"IOC type not defined for {ioc}.")
            results["error"] = 'IOC type not supported.'
            return web.json_response(results)
            
        self.logger.info("Starting async checks for modules {}".format([module.__class__.__name__ for module in self.modules]))
        
        tasks = []
        for module in self.modules:
            if module.supports_ioc_type(ioc_type):
                module_name = module.__class__.__name__
                task = self._create_async_task(
                    module_name, 
                    module.process_ioc, 
                    ioc_type, 
                    ioc
                )
                tasks.append(task)
            else:
                self.logger.debug(f"Skipping {module.__class__.__name__} - doesn't support {ioc_type}")

        module_results = await asyncio.gather(*tasks)

        processed_results = []
        timeout_modules = []
        for result in module_results:
            module_name, result = result
            if isinstance(result, Exception):
                if isinstance(result, asyncio.TimeoutError):
                    timeout_modules.append(module_name)
                    error_msg = "Module timed out"
                else:
                    error_msg = str(result)
                entry = (module_name, {"error": error_msg})
            elif result is not None:
                entry = (module_name, result)
            else:
                continue
            processed_results.append(entry)

        if timeout_modules:
            self.logger.warning(f"Modules {timeout_modules} timed out")
            results["warning"] = "Partial results due to timeout"

        processed_results.sort(
            key=lambda x: not x[1].get('status', False)
        )
        sorted_results = {k: v for k, v in processed_results}
        
        return web.json_response({
            "ioc": self.defanger.defang(ioc),
            "type": ioc_type.upper(),
            "results": sorted_results
        })
    
    async def update_modules(self, request: web.Request) -> web.Response:
        '''Update modules

        :param request: aiohttp request object
        '''
        return web.json_response({"status": "completed"})


def load_config(basedir: str) -> Dict:
    '''Load configuration

    :param basedir: Root directory
    '''
    try:
        conf_path = os.path.join(basedir, 'config', 'global.yaml')
        log_path = os.path.join(basedir, 'logs', 'malwatcher.log')
        with open(conf_path, "r") as file:
            config = yaml.safe_load(file)
    except Exception as e:
        with open(log_path, "a") as file:
            file.write(f"[CRITICAL] Error while loading configuration: {e}\n")
        sys.exit(1)
    return config

def setup_logger(config: Dict) -> logging.Logger:
    '''Setup logger

    :param config: Configuration dict
    '''
    try:
        logger = logging.getLogger(__name__)
        logger.setLevel(getattr(logging, config["logging"]["worker"]['level'].upper()))
        handler = logging.FileHandler(config["logging"]["worker"]["file"])
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] {"WORKER"} %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    except Exception as e:
        with open(config["logging"]["worker"]["file"], "a") as file:
            file.write(f"[CRITICAL] Error while setting up logging: {e}\n")
        sys.exit(1)
    return logger

if __name__ == "__main__":
    basedir = os.path.dirname(sys.argv[0])
    config = load_config(basedir)
    logger = setup_logger(config)

    logger.info("Starting worker")

    module_loader = ModuleLoader()
    modules = module_loader.load_modules()

    worker = Worker(logger, config, modules)
    app = web.Application()
    app.router.add_post('/check', worker.check_ioc)
    app.router.add_post('/update', worker.update_modules)
    web.run_app(app, host="worker", port=8080)
