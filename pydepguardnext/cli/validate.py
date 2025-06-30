# pydepguardnext/cli/generate.py

from pathlib import Path
from time import time
from pydepguardnext.api.log.logit import logit
from pydepguardnext.api.deps.walker import scan_script_for_imports
from pydepguardnext.api.deps.enrich import enrich_module
from pydepguardnext.api.deps.lockfile import DepMapRegistry
from pydepguardnext.api.lockfile.manager import LockfileManager
from .shared import setup_logging

def add_generate_command(subparsers):
    parser = subparsers.add_parser("generate", help="Generate lockfile from a script")
    parser.add_argument("script", help="Script to scan for dependencies")
    parser.set_defaults(handler=handle_generate)

def handle_generate(args):
    setup_logging(args)
    script_path = Path(args.script).resolve()
    if not script_path.exists():
        logit(f"Script not found: {script_path}", "e")
        return

    logit("[pydepguard] Scanning for imports...", "i")
    start_time = time()

    imports, unbound_symbols = scan_script_for_imports(script_path)
    logit(f"Found {len(unbound_symbols)} unbound symbols.", "w")
    for sym in unbound_symbols:
        logit(f"Unbound Symbol: {sym.name} at {sym.file}:{sym.line} — consider adding `import {sym.name}`", "w")

    registry = DepMapRegistry()
    for ref in imports:
        modname = ref.module.split('.')[0]
        depmap = enrich_module(modname)
        depmap.add_alias(ref.module)
        for ver in depmap.versions:
            depmap.add_version(ver, source=ref.context)
        registry._registry[depmap.pypi_name] = depmap

    lm = LockfileManager(script_path)
    lm.save(registry.to_lockfile())

    logit(f"[pydepguard] Lockfile generated for {script_path.name} with {len(registry._registry)} dependencies.", "i")
    logit(f"[pydepguard] Total Time Spent: {time() - start_time:.8f} seconds", "d")
    logit("If this saved you time, star or sponsor: https://github.com/nuclear-treestump/pylock-dependency-lockfile", "i")
