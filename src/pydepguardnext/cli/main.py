# cli/main.py
import argparse
import sys
from .run import add_run_command
from .shared import setup_logging
from .validate import add_validate_command
from .generate import add_generate_command
# from .compat import add_run_command as compat_add_run_command

def main_cli_input():
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
    add_run_command(subparsers)
    add_validate_command(subparsers)
    add_generate_command(subparsers)

    # compat_add_run_command(subparsers)

    args = parser.parse_args()


    setup_logging(args)


    if hasattr(args, "handler"):
        args.handler(args)
    else:
        parser.print_help()
        sys.exit(1)
