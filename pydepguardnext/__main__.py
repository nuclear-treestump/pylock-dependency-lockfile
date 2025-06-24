import argparse
import sys
from pathlib import Path
from pydepguardnext.api.runtime.guard import run_with_repair
from pydepguardnext.api.runtime.no_guard import run_without_guard
from pydepguardnext.api.log.logit import logit, configure_logging, LOG_LEVELS
from pydepguardnext.api.runtime.integrity import INTEGRITY_CHECK


def main():
    from pydepguardnext import _log, get_gtime
    parser = argparse.ArgumentParser(
        description="PyDepGuard CLI v4.0.0\nMade by 0xIkari\nGet it here: https://github.com/nuclear-treestump/pylock-dependency-lockfile\nIf this helped you, please consider sponsoring. Thank you!\n\n"
                    "Supports direct script execution with optional repair.\n"
                    "Use --no-repair to bypass fallback healing logic."
    )
    parser.add_argument("script", help="Python script to run")
    parser.add_argument("--run", action="store_true", help="Run the script after validation")
    parser.add_argument("--repair", action="store_true", help="Enable automatic dependency repair")
    parser.add_argument("--stdin-ok", action="store_true", help="Allow stdin passthrough to script")
    parser.add_argument("--log-level", default="info", choices=["debug", "info", "warning", "error", "critical"],
                        help="Set the logging level (default: debug)")
    parser.add_argument("--log-file", default=None, help="Optional log file path to write logs to (default: pydepguard.log)")
    parser.add_argument("--format", default="text", choices=["text", "json"], help="Set log format (default: text)")
    parser.add_argument("--noprint", action="store_true", help="Disable console output for logs")
    parser.add_argument("--lambda", action="store_true", help="Run in Lambda mode")
    parser.add_argument("--fakeroot", action="store_true", help="Prepare a fakeroot environment for the script using PyDepGuard's AirJail")
    parser.add_argument("--lambda-directory", default=None, help="Directory to create the Lambda environment in (default: current directory)")
    parser.add_argument("--harden-execution", default="none", choices=["none", "low", "medium", "high", "maxsec"], 
                        help="Set the hardening level for script execution (default: none)")
    parser.add_argument("--dev", action="store_true", help="Enable development mode. This can also be set by setting PYDEPHARDEN=0. In the event you invoke something here, it will override ENV choices. This is by design. This is not recommended for production use and is intended for development purposes only.")
    parser.add_argument("--ci", action="store_true", help="Enable continuous integration mode. This turns on additional checks and logging suitable for CI environments. This is not recommended for production use as it may be noisy and verbose.")
    parser.add_argument("--daemon", action="store_true", help="Run in daemon mode. This will start a background process that starts a web server to receive scripts to run and return results. This is useful for integrating PyDepGuard into other systems or for running scripts in a controlled environment. Note that this mode is experimental and may not work as expected. Use at your own risk.")
    parser.add_argument("--daemon-port", type=int, default=8080, help="Port for the daemon to listen on (default: 8080)")
    parser.add_argument("--daemon-block-external", action="store_true", help="Block external access to the daemon. This will only allow connections from localhost. This is useful for running the daemon in a secure environment where you don't want external access. Note that this mode is experimental and may not work as expected. Use at your own risk.")
    parser.add_argument("--daemon-allow-external", action="store_true", help="Allow external access to the daemon. This will allow connections from any IP address. This is useful for running the daemon in a public environment where you want external access. Note that this mode is experimental and may not work as expected. Use at your own risk.")
    parser.add_argument("--daemon-config", default=None, help="Path to a JSON configuration file for the daemon. This file can contain additional settings for the daemon such as allowed IP addresses, authentication settings, etc. If not provided, the daemon will use default settings. Note that this mode is experimental and may not work as expected. Use at your own risk.")
    parser.add_argument("--daemon-ssl", action="store_true", help="Enable SSL for the daemon. This will start the daemon with SSL enabled. You must provide a certificate and key file using --daemon-ssl-cert and --daemon-ssl-key. Note that this mode is experimental and may not work as expected. Use at your own risk.")
    parser.add_argument("--daemon-ssl-cert", default=None, help="Path to the SSL certificate file for the daemon. This is required if --daemon-ssl is enabled. Note that this mode is experimental and may not work as expected. Use at your own risk.")
    parser.add_argument("--daemon-log-level", default="info", choices=["debug", "info", "warning", "error", "critical"],
                        help="Set the logging level for the daemon (default: info)")
    parser.add_argument("--daemon-log-file", default=None, help="Optional log file path for the daemon (default: pydepguard_daemon.log)")
    parser.add_argument("--daemon-noprint", action="store_true", help="Disable console output for daemon logs")
    parser.add_argument("--daemon-format", default="text", choices=["text", "json"], help="Set log format for daemon logs (default: text)")
    parser.add_argument("--daemon-allow-remote", action="store_true", help="Allow remote access to the daemon. This will allow connections from any IP address. This is useful for running the daemon in a public environment where you want external access. Note that this mode is experimental and may not work as expected. Use at your own risk.")
    parser.add_argument("--use-syslog", action="store_true", help="Use syslog for logging. Must provide a --syslog-config file. This is useful for integrating PyDepGuard with system logging services. Note that this mode is experimental and may not work as expected. Use at your own risk.")
    parser.add_argument("--syslog-config", default=None, help="Path to the syslog configuration file. This file can contain additional settings for syslog such as server address, port, etc. If not provided, the daemon will use default settings. Note that this mode is experimental and may not work as expected. Use at your own risk.")
    parser.add_argument("--syslog-level", default="info", choices=["debug", "info", "warning", "error", "critical"],
                        help="Set the syslog logging level (default: info)")
    parser.add_argument("--log-custom-http-output", action="store_true", help="Enable custom HTTP output for logs. This will send logs to a custom HTTP endpoint. You must provide a --log-http-endpoint. This is useful for integrating PyDepGuard with external logging.")
    parser.add_argument("--log-http-endpoint", default=None, help="HTTP endpoint to send logs to. This is required if --log-custom-http-output is enabled. This is useful for integrating PyDepGuard with external logging services.")
    # parser.add_argument("--")

    args = parser.parse_args()
    script_path = Path(args.script).resolve()
    skip_print = False
    if args.noprint:
        skip_print = True

    if args.log_file:
        (print(f"[{get_gtime()}] [.__main__] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] Logging to file: {args.log_file} (Use --log-file to specify a different path)") if not skip_print else _log.append(f"[{get_gtime()}] [.__main__] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] Logging to file: {args.log_file} (Use --log-file to specify a different path)"))

    if args.log_level:
        (print(f"[{get_gtime()}] [.__main__] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] Setting log level to: {args.log_level}") if not skip_print else _log.append(f"[{get_gtime()}] [.__main__] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] Setting log level to: {args.log_level}"))

    if args.format:
        (print(f"[{get_gtime()}] [.__main__] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] Setting log format to: {args.format}") if not skip_print else _log.append(f"[{get_gtime()}] [.__main__] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] Setting log format to: {args.format}"))

    if args.noprint:
        (print(f"[{get_gtime()}] [.__main__] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] Console output disabled for logs") if not skip_print else _log.append(f"[{get_gtime()}] [.__main__] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] Console output disabled for logs"))

    configure_logging(
        level=(args.log_level or "debug"),
        to_file=(args.log_file or "pydepguard.log"),
        fmt=(args.format or "text"),
        print_enabled=not args.noprint,
        initial_logs=_log
    )

    if not script_path.exists():
        logit(f"File not found: {script_path}", "e", source="__main__.main")
        sys.exit(1)

    if not script_path.is_file():
        logit(f"Path is not a file: {script_path}", "e", source="__main__.main")
        sys.exit(1)

    if not script_path.suffix == ".py":
        logit(f"Script must be a Python file: {script_path}", "e", source="__main__.main")
        sys.exit(1)

    if args.stdin_ok:
        logit("Stdin passthrough enabled, script will receive stdin input", "i", source="__main__.main")

    if args.run:
        logit("Preparing to run script", "i", source="__main__.main")
        if args.repair:
            logit("Running with repair logic enabled", "i", source="__main__.main")
            run_with_repair(str(script_path))
        else:
            logit("Running script without repair logic", "i", source="__main__.main")
            run_without_guard(str(script_path))

    else:
        print(f"No actions specified. Use --run to execute the script.", file=sys.stderr)

if __name__ == "__main__":
    main()
