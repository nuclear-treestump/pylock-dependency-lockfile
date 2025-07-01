# cli/main.py
import argparse
import sys
from .run import add_run_command
from .shared import setup_logging
from .validate import add_validate_command
from .generate import add_generate_command
from .compat import add_run_command as compat_add_run_command

def main():
    parser = argparse.ArgumentParser(
        description="PyDepGuard CLI v4.x — Runtime Integrity Gatekeeper"
    )
    subparsers = parser.add_subparsers(dest="command", required=False)

    # Add subcommands
    setup_logging(parser)
    add_run_command(subparsers)
    add_validate_command(subparsers)
    add_generate_command(subparsers)
    compat_add_run_command(subparsers)

    args = parser.parse_args()

    if hasattr(args, "handler"):
        args.handler(args)
    else:
        parser.print_help()
        sys.exit(1)
