import argparse
import sys
from pathlib import Path
from pydepguardnext.api.runtime.guard import run_with_repair
from pydepguardnext.api.runtime.no_guard import run_without_guard
from pydepguardnext.api.log.logit import logit, configure_logging, LOG_LEVELS
from pydepguardnext.api.runtime.integrity import INTEGRITY_CHECK

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
    parser.add_argument("--log-level", default="info", choices=["debug", "info", "warning", "error", "critical"],
                        help="Set the logging level (default: info)")
    parser.add_argument("--log-file", default=None, help="Optional log file path to write logs to (default: pydepguard.log)")
    parser.add_argument("--format", default="text", choices=["text", "json"], help="Set log format (default: text)")
    parser.add_argument("--noprint", action="store_true", help="Disable console output for logs")

    args = parser.parse_args()
    script_path = Path(args.script).resolve()

    if args.log_file:
        print(f"[pydepguard.__main__] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] Logging to file: {args.log_file} (Use --log-file to specify a different path)")

    if args.log_level:
        print(f"[pydepguard.__main__] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] Setting log level to: {args.log_level}")

    if args.format:
        print(f"[pydepguard.__main__] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] Setting log format to: {args.format}")

    if args.noprint:
        print(f"[pydepguard.__main__] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] Console output disabled for logs")

    configure_logging(
        level=(args.log_level or "debug"),
        to_file=(args.log_file or "pydepguard.log"),
        fmt=(args.format or "text"),
        print_enabled=not args.noprint
    )

    if not script_path.exists():
        logit(f"File not found: {script_path}", "e", source="__main__.main")
        sys.exit(1)

    if not script_path.is_file():
        logit(f"Path is not a file: {script_path}", "e", source="__main__.main")
        sys.exit(1)

    if not script_path.suffix == ".py":
        logit(f"Script must be a Python file: {script_path}", "e", source="__main__.main")
        sys.exit(1)

    if args.stdin_ok:
        logit("Stdin passthrough enabled, script will receive stdin input", "i", source="__main__.main")

    if args.run:
        logit("Preparing to run script", "i", source="__main__.main")
        if args.repair:
            logit("Running with repair logic enabled", "i", source="__main__.main")
            run_with_repair(str(script_path))
        else:
            logit("Running script without repair logic", "i", source="__main__.main")
            run_without_guard(str(script_path))

    else:
        print(f"No actions specified. Use --run to execute the script.", file=sys.stderr)

if __name__ == "__main__":
    main()
