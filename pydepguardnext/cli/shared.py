from pydepguardnext.api.log.logit import configure_logging
from pydepguardnext.bootstrap import clock
from pydepguardnext.bootstrap.boot import JIT_DATA_BUNDLE

logslug = "cli.shared"

def setup_logging(args):
    gid = JIT_DATA_BUNDLE.get("jit_check_uuid", "unknown")

    if args.log_file:
        print(f"[{clock.timestamp()}] [.__main__.cli.shared] [{gid}] Logging to file: {args.log_file}")

    if args.log_level:
        print(f"[{clock.timestamp()}] [.__main__.cli.shared] [{gid}] Setting log level to: {args.log_level}")

    if args.format:
        print(f"[{clock.timestamp()}] [.__main__.cli.shared] [{gid}] Setting log format to: {args.format}")

    if args.noprint:
        print(f"[{clock.timestamp()}] [.__main__.cli.shared] [{gid}] Console output disabled for logs")

    configure_logging(
        level=(args.log_level or "debug"),
        to_file=(args.log_file or "pydepguard.log"),
        fmt=(args.format or "text"),
        print_enabled=not args.noprint,
        initial_logs=_log
    )
