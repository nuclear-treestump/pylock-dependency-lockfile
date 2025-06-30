from pathlib import Path
from pydepguardnext.api.runtime.guard import run_with_repair
from pydepguardnext.api.runtime.no_guard import run_without_guard
from pydepguardnext.api.log.logit import logit
import sys

def add_run_command(subparsers):
    parser = subparsers.add_parser("run", help="Run a Python script")
    parser.add_argument("script", help="Python script to execute")
    parser.add_argument("--repair", action="store_true", help="Enable dependency repair if needed")
    parser.add_argument("--stdin-ok", action="store_true", help="Allow stdin passthrough")
    parser.set_defaults(handler=handle_run)

def handle_run(args):
    script = Path(args.script).resolve()
    if not script.exists() or not script.is_file() or script.suffix != ".py":
        logit(f"Invalid script path: {script}", "e")
        sys.exit(1)

    logit("Running script", "i")
    if args.repair:
        logit("Repair mode active", "i")
        run_with_repair(str(script))
    else:
        run_without_guard(str(script))
