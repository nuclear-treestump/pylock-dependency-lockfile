import argparse
import sys
from pathlib import Path
from .depscan import scan_script_for_imports
from .lockfile import LockfileManager
from .validator import validate_environment
from .runner import execute_script
from .utils import enrich_dependencies

def main():
    parser = argparse.ArgumentParser(
        description="PyLock: A gatekeeper dependency validator for Python scripts.\n"
                    "This tool scans Python scripts for imports, generates lockfiles, and validates dependencies.\n"
                    "Version 1.0 - Made by 0xIkari\n"
                    "Usage: pylock script.py [options]\n\n"
                    "Options:\n"
                    "  --generate     Generate or overwrite a per-file lockfile\n"
                    "  --validate     Validate environment against lockfile\n"
                    "  --run          Run the script if validation passes\n",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('script', help="Script to check and run")
    parser.add_argument('-g', '--generate', action='store_true', help="Generate or overwrite per-file lockfile")
    parser.add_argument('-v', '--validate', action='store_true', help="Validate environment against lockfile only")
    parser.add_argument('-r', '--run', action='store_true', help="Run the script if validation passes")
    args = parser.parse_args()

    script_path = Path(args.script)
    if not script_path.exists():
        print(f"[pylock] Error: File not found: {script_path}", file=sys.stderr)
        sys.exit(1)

    lm = LockfileManager(script_path)

    if args.generate or not lm.exists():
        print("[pylock] Scanning for imports...")
        imports = scan_script_for_imports(script_path)
        deps = enrich_dependencies(imports)
        lm.save(deps)
        return

    if args.validate or args.run:
        lockfile = lm.load()
        validate_environment(lockfile)
        if args.run:
            execute_script(args.script)
        return
    
    parser.print_help()
