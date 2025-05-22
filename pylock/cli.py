import argparse
from pathlib import Path
from .depscan import scan_script_for_imports
from .lockfile import LockfileManager
from .validator import validate_environment
from .runner import execute_script


def main():
    parser = argparse.ArgumentParser(description="PyLock Dependency Enforcer")
    parser.add_argument('script', help="Script to check and run")
    parser.add_argument('-g', '--generate', action='store_true', help="Generate lockfile")
    args = parser.parse_args()

    lm = LockfileManager(args.script)

    if args.generate or not lm.exists():
        print("Scanning for imports...")
        imports = scan_script_for_imports(Path(args.script))
        deps = {imp.module: {} for imp in imports}
        lm.save(deps)
    else:
        lockfile = lm.load()
        validate_environment(lockfile)
        execute_script(args.script)