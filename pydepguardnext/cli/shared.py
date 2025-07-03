from pydepguardnext.api.log.logit import configure_logging
from pydepguardnext.bootstrap import clock

logslug = "cli.shared"

def setup_logging(args):
    gid = GLOBAL_INTEGRITY_CHECK.get("global_.jit_check_uuid", "unknown")

    if args.log_file:
        _log.append(f"[{clock.timestamp()}] [.__main__] [{gid}] Logging to file: {args.log_file}")

    if args.log_level:
        _log.append(f"[{clock.timestamp()}] [.__main__] [{gid}] Setting log level to: {args.log_level}")

    if args.format:
        _log.append(f"[{clock.timestamp()}] [.__main__] [{gid}] Setting log format to: {args.format}")

    if args.noprint:
        _log.append(f"[{clock.timestamp()}] [.__main__] [{gid}] Console output disabled for logs")

    configure_logging(
        level=(args.log_level or "debug"),
        to_file=(args.log_file or "pydepguard.log"),
        fmt=(args.format or "text"),
        print_enabled=not args.noprint,
        initial_logs=_log
    )
