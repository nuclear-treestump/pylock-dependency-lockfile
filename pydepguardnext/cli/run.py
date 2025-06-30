from pathlib import Path
import sys
from pydepguardnext.api.runtime.guard import run_with_repair
from pydepguardnext.api.runtime.no_guard import run_without_guard
from pydepguardnext.api.log.logit import logit
from pydepguardnext.api.policy.context import PDGContext, load_policy_context
from .shared import setup_logging

logslug = "cli.run"

def add_run_command(subparsers):
    parser = subparsers.add_parser("run", help="Run a Python script")
    parser.add_argument("script", help="Python script to execute")
    parser.add_argument("--repair", action="store_true", help="Enable dependency repair if needed")
    parser.add_argument("--stdin-ok", action="store_true", help="Allow stdin passthrough")
    parser.add_argument("--strict", action="store_true", help="Enable strict version matching")
    parser.add_argument("--non-interactive", action="store_true", help="Disable prompts (CI mode). This will skip all interactive prompts and assume defaults.")
    parser.add_argument("--yes", action="store_true", help="Assume 'yes' to all prompts (use with caution)")
    parser.add_argument("--on-error", choices=["abort", "warn", "skip"], default="abort", help="Error handling mode")
    parser.add_argument("--policy", help="Path to .pdgpolicy file to load context and runtime policy")

    parser.set_defaults(handler=handle_run)

def handle_run(args):
    setup_logging(args)
    script = Path(args.script).resolve()
    if not script.exists() or not script.is_file() or script.suffix != ".py":
        logit(f"Invalid script path: {script}", "e", source=f"{logslug}.{handle_run.__name__}")
        sys.exit(1)

    if args.policy:
        ctx = load_policy_context(Path(args.policy))
        logit(f"Using runtime context: {ctx.id()}", "i")
    else:
        ctx = PDGContext()    
    
    logit("Running script", "i", source=f"{logslug}.{handle_run.__name__}")
    if args.repair:
        logit("Repair mode active", "i", source=f"{logslug}.{handle_run.__name__}")
        run_with_repair(str(script))
    else:
        run_without_guard(str(script))