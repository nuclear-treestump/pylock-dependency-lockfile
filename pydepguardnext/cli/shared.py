from pydepguardnext.api.log.logit import configure_logging
from pydepguardnext import _log, get_gtime, INTEGRITY_CHECK

logslug = "cli.shared"

def setup_logging(args):
    skip_print = args.noprint
    gid = INTEGRITY_CHECK.get("global_.jit_check_uuid", "unknown")

    def maybe_log(msg):
        if not skip_print:
            print(msg)
        else:
            _log.append(msg)

    if args.log_file:
        maybe_log(f"[{get_gtime()}] [.__main__] [{gid}] Logging to file: {args.log_file}")

    if args.log_level:
        maybe_log(f"[{get_gtime()}] [.__main__] [{gid}] Setting log level to: {args.log_level}")

    if args.format:
        maybe_log(f"[{get_gtime()}] [.__main__] [{gid}] Setting log format to: {args.format}")

    if args.noprint:
        maybe_log(f"[{get_gtime()}] [.__main__] [{gid}] Console output disabled for logs")

    configure_logging(
        level=(args.log_level or "debug"),
        to_file=(args.log_file or "pydepguard.log"),
        fmt=(args.format or "text"),
        print_enabled=not args.noprint,
        initial_logs=_log
    )
