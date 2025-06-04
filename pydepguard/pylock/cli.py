import argparse
import sys
import json
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
                    "Version 2.0.0 - Made by 0xIkari\n"
                    "Part of the PyDepGuard project\n"
                    "Usage: pylock script.py [options]\n\n"
                    "Options:\n"
                    "  --generate         Generate or overwrite per-file lockfile\n"
                    "  --validate         Validate environment against lockfile\n"
                    "  --run              Run the script if validation passes\n"
                    "  --strict           Enable strict version matching\n"
                    "  --non-interactive  Disable user input (e.g., for CI/CD)\n"
                    "  --on-error         Set behavior on errors: 'abort', 'warn', or 'skip'\n",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('script', nargs='?', help="Script to check and run")
    parser.add_argument('-g', '--generate', action='store_true')
    parser.add_argument('-v', '--validate', action='store_true')
    parser.add_argument('-r', '--run', action='store_true')
    parser.add_argument('--strict', action='store_true')
    parser.add_argument('--non-interactive', action='store_true')
    parser.add_argument('--on-error', choices=['abort', 'warn', 'skip'], default='abort')

    args = parser.parse_args()

    if not args.script:
        parser.print_help()
        sys.exit(1)

    script_path = Path(args.script)
    if not script_path.exists():
        print(f"[pylock] Error: File not found: {script_path}", file=sys.stderr)
        sys.exit(1)

    lm = LockfileManager(script_path)

    if args.generate:
        print("[pylock] Scanning for imports...")
        imports, unbound_symbols = scan_script_for_imports(script_path)
        print(f"[pylock] Found {len(unbound_symbols)} unbound symbols.")
        unbound_findings = list()
        for sym in unbound_symbols:
            unbound_findings.append(f"File: {sym.file} Module: {sym.name} Line Number: {sym.line})")
            print(f"[pylock.CRIT] Unbound Symbol: {sym.name} at {sym.file}:{sym.line} - Add `import {sym.name}` to {sym.file} resolve.")
        deps = enrich_dependencies(imports)
        lm.save(deps)
        return

    if args.validate or args.run:
        if not lm.exists():
            print(f"[pylock] Error: No lockfile found for {script_path.name}. Please run with --generate first.", file=sys.stderr)
            sys.exit(1)

        lockfile = lm.load()
        validate_environment(
            lockfile,
            strict=args.strict,
            interactive=not args.non_interactive,
            on_error=args.on_error
        )
        if args.run:
            execute_script(args.script)
        return

    print("[pylock] No action specified. Use --generate, --validate, or --run.\n")
    parser.print_help()