import argparse
import sys
from pathlib import Path
from pydepguardnext.api.runtime.guard import run_with_repair
from pydepguardnext.api.runtime.no_guard import run_without_guard
from pydepguardnext.api.log.logit import logit

def main():
    parser = argparse.ArgumentParser(
        description="PyDepGuard CLI v4.0.0\nMade by 0xIkari\nGet it here: https://github.com/nuclear-treestump/pylock-dependency-lockfile\nIf this helped you, please consider sponsoring. Thank you!\n\n"
                    "Supports direct script execution with optional repair.\n"
                    "Use --no-repair to bypass fallback healing logic."
    )
    parser.add_argument("script", help="Python script to run")
    parser.add_argument("--run", action="store_true", help="Run the script after validation")
    parser.add_argument("--repair", action="store_true", help="Enable automatic dependency repair")
    parser.add_argument("--stdin-ok", action="store_true", help="Allow stdin passthrough to script")

    args = parser.parse_args()
    script_path = Path(args.script).resolve()

    if not script_path.exists():
        logit(f"File not found: {script_path}", "e")
        sys.exit(1)

    if not script_path.is_file():
        logit(f"Path is not a file: {script_path}", "e")
        sys.exit(1)

    if not script_path.suffix == ".py":
        logit(f"Script must be a Python file: {script_path}", "e")
        sys.exit(1)

    if args.stdin_ok:
        logit("Stdin passthrough enabled, script will receive stdin input", "i")

    if args.run:
        logit("Preparing to run script", "i")
        if args.repair:
            logit("Running with repair logic enabled", "i")
            run_with_repair(str(script_path))
        else:
            logit("Running script without repair logic", "i")
            run_without_guard(str(script_path))

    else:
        print(f"No actions specified. Use --run to execute the script.", file=sys.stderr)

if __name__ == "__main__":
    main()
