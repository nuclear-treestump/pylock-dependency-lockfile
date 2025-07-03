from pathlib import Path
import sys
from pydepguardnext.api.runtime.guard import run_with_repair
from pydepguardnext.api.runtime.no_guard import run_without_guard
from pydepguardnext.api.log.logit import logit
from pydepguardnext.api.policy.context import PDGContext, load_policy_context
from pydepguardnext.api.runtime.integrity import jit_check
from .shared import setup_logging

logslug = "cli.run"

def add_run_command(subparsers):
    parser = subparsers.add_parser("run", help="Run a Python script")
    parser.add_argument("script", help="Python script to execute. If using stdin for args, you must use --script. If you want to run a script from stdin, use - for the script path. This may not work with all scripts.")
    parser.add_argument("--named", type=str, default=None, help="Run existing named lambda script. Use - for stdin passthrough")
    parser.add_argument("--repair", action="store_true", help="Enable dependency repair if needed")
    parser.add_argument("--stdin-ok", action="store_true", help="Allow stdin passthrough")
    parser.add_argument("--strict", action="store_true", help="Enable strict version matching")
    parser.add_argument("--non-interactive", action="store_true", help="Disable prompts (CI mode). This will skip all interactive prompts and assume defaults.")
    parser.add_argument("--yes", action="store_true", help="Assume 'yes' to all prompts (use with caution)")
    parser.add_argument("--on-error", choices=["abort", "warn", "skip"], default="abort", help="Error handling mode")
    parser.add_argument("--policy", help="Path to .pdgpolicy file to load context and runtime policy")
    parser.add_argument("--lambda", help="Run in Lambda mode. This creates a run-once environment, unless --persist=True", action="store_true", default=False, dest="lambda_mode")
    parser.add_argument("--persist", action="store_true", help="Persist the Lambda environment for future runs. This is only effective when used with --lambda.")
    parser.add_argument("--teardown", type=float, default=-1.0, help="Teardown time in seconds for Lambda mode. This will kill the Lambda environment after the specified time. Default is -1 (no teardown).")
    parser.add_argument("--lambda_path", type=str, default=None, help="Path to the Lambda environment directory. If not specified, a temporary directory will be used under ./.pydepguardenv/lambda/<hash>")
    parser.add_argument("--lambda_name", type=str, default=None, help="Name of the Lambda environment. If not specified, a hash will be generated from the script path and other parameters. Cannot be used without --persist")
    parser.add_argument("--prewarm", action="store_true", help="Prewarm the Lambda environment before running the script. This is only effective when used with --lambda. This will parse top-level imports and install them in the Lambda environment before running the script. This is useful for reducing cold start times in Lambda environments.")

    parser.set_defaults(handler=handle_run)

def handle_run(args):
    print("ENTERING HANDLE_RUN")
    print("ID OF JIT_CHECK:", id(jit_check))
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

    if args.lambda_mode:
        from pydepguardnext.api.run.lambda_runner import run_lambda_script
        run_lambda_script(script, ctx, args)
    
    logit("Running script", "i", source=f"{logslug}.{handle_run.__name__}")
    if args.repair:
        logit("Repair mode active", "i", source=f"{logslug}.{handle_run.__name__}")
        print("ID OF JIT_CHECK:", id(jit_check))
        run_with_repair(str(script))
    else:
        run_without_guard(str(script))