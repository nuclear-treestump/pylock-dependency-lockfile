# cli/main.py
import argparse
import sys
from .run import add_run_command
from .shared import setup_logging
from .validate import add_validate_command
from .generate import add_generate_command
from pydepguardnext.api.runtime.integrity import jit_check
# from .compat import add_run_command as compat_add_run_command

def main_cli_input():
    print("ENTERING MAIN")
    print("ID OF JIT_CHECK:", id(jit_check))
    parser = argparse.ArgumentParser(
        description="PyDepGuard CLI v4.x — Runtime Integrity Gatekeeper"
    )
    parser.add_argument("--noprint", action="store_true", help="Disable console output")
    parser.add_argument("--log-level", help="Log level", default="debug")
    parser.add_argument("--log-file", help="Log file name")
    parser.add_argument("--format", help="Log format", default="text")
    # explicit command for telling PDG to run as other roles. Will be used in future for more significantly more complex scenarios.
    parser.add_argument("--as", default="parent", choices=["global","dev","multiverse", "universe","plane","dim","parent", "child"], help=argparse.SUPPRESS)  
    subparsers = parser.add_subparsers(dest="command", required=False)

    # Add subcommands
    print("ADDING COMMANDS")
    add_run_command(subparsers)
    print("PROCESSED RUN COMMAND ADD")
    print("ID OF JIT_CHECK:", id(jit_check))
    add_validate_command(subparsers)
    print("PROCESSED VALIDATE COMMAND ADD")
    print("ID OF JIT_CHECK:", id(jit_check))
    add_generate_command(subparsers)
    print("PROCESSED GENERATE COMMAND ADD")
    print("ID OF JIT_CHECK:", id(jit_check))
    # compat_add_run_command(subparsers)

    args = parser.parse_args()
    print("PARSED ARGS")
    print("ID OF JIT_CHECK:", id(jit_check))

    setup_logging(args)
    print("SETUP LOGGING")
    print("ID OF JIT_CHECK:", id(jit_check))

    if hasattr(args, "handler"):
        print("CALLING HANDLER")
        print("ID OF JIT_CHECK:", id(jit_check))
        args.handler(args)
    else:
        parser.print_help()
        sys.exit(1)
