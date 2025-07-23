from pathlib import Path
import sys
from pydepguardnext.api.log.logit import logit
from pydepguardnext.api.lockfile.manager import LockfileManager
from pydepguardnext.api.compat.validator import validate_environment_legacy as validate_environment
from .shared import setup_logging

logslug = "cli.validate"

def add_validate_command(subparsers):
    parser = subparsers.add_parser("validate", help="Validate environment against lockfile")
    parser.add_argument("script", help="Script to validate")
    parser.add_argument("--strict", action="store_true", help="Enable strict version matching")
    parser.add_argument("--non-interactive", action="store_true", help="Disable user prompts")
    parser.add_argument("--on-error", choices=["abort", "warn", "skip"], default="abort", help="What to do on validation error")
    parser.set_defaults(handler=handle_validate)

def handle_validate(args):
    setup_logging(args)
    script = Path(args.script).resolve()
    if not script.exists():
        logit(f"Script not found: {script}", "e", source=f"{logslug}.{handle_validate.__name__}")
        sys.exit(1)

    lm = LockfileManager(script)
    if not lm.exists():
        logit(f"No lockfile exists for {script.name}. Use generate first.", "e", source=f"{logslug}.{handle_validate.__name__}")
        sys.exit(1)

    try:
        lockfile = lm.load()
        validate_environment(lockfile)
        logit("Validation passed.", "i", source=f"{logslug}.{handle_validate.__name__}")
    except RuntimeError as e:
        if args.on_error == "warn":
            logit(f"Validator Warn Error: {e}", "w", source=f"{logslug}.{handle_validate.__name__}")
        elif args.on_error == "skip":
            logit(f"Validator Skip Error: {e}", "w", source=f"{logslug}.{handle_validate.__name__}")
        else:
            logit(f"{e}", "e", source=f"{logslug}.{handle_validate.__name__}")
            sys.exit(1)
