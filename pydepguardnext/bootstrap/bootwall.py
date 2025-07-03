

from datetime import datetime
from pathlib import Path
import json
import shutil
from pydepguardnext.bootstrap import clock
from types import MappingProxyType

class ANSI:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    HEADER = "\033[95m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    GREY = "\033[90m"

def render_boot_wall(fingerprint_data, fingerprint_hash, jit_data, signature_data=None, system_state="insecure", package="package", version="version"):
    data = {
        "status": system_state,
        "timestamp": clock.timestamp("iso_utc"),
        "uuid": jit_data.get("jit_check_uuid", "unknown") if jit_data else "unknown",
        "version": version,
        "runtime": {
            "uptime_sec": clock.since_boot(),
            "uuid": jit_data.get("jit_check_uuid", "unknown") if jit_data else "unknown",
            "package": package,
            "version": version,
            "fingerprint_hash": fingerprint_hash
        },
        "system": {
            "hostname": fingerprint_data.get("hostname", "unknown") if fingerprint_data else "unknown",
            "os": fingerprint_data.get("os", "unknown") if fingerprint_data else "unknown",
            "os_release": fingerprint_data.get("os_release", "unknown") if fingerprint_data else "unknown",
            "os_version": fingerprint_data.get("os_version", "unknown") if fingerprint_data else "unknown",
            "arch": fingerprint_data.get("arch", "unknown") if fingerprint_data else "unknown",
            "platform": fingerprint_data.get("platform", "unknown") if fingerprint_data else "unknown",
            "user": fingerprint_data.get("user", "unknown") if fingerprint_data else "unknown",
            "cpu": {
                "processor": fingerprint_data.get("processor", "unknown") if fingerprint_data else "unknown",
                "count": fingerprint_data.get("cpu_count", "0") if fingerprint_data else 0
            },
            "memory": {
                "gb": fingerprint_data.get("total_memory_gb", 0) if fingerprint_data else 0,
                "gib": fingerprint_data.get("total_memory_gib", 0) if fingerprint_data else 0
            }
        },
        "python": {
            "version": fingerprint_data.get("python_version", "unknown") if fingerprint_data else "unknown",
            "build": fingerprint_data.get("python_build", ["unknown"]) if fingerprint_data else ["unknown"],
            "compiler": fingerprint_data.get("python_compiler", "unknown") if fingerprint_data else "unknown",
            "abs_path": fingerprint_data.get("python_abs_path", "unknown") if fingerprint_data else "unknown",
            "interpreter_hash": fingerprint_data.get("python_interpreter_hash", "unknown") if fingerprint_data else "unknown",
            "cwd": fingerprint_data.get("cwd", "unknown") if fingerprint_data else "unknown",
            "executable": fingerprint_data.get("executable", "unknown") if fingerprint_data else "unknown"
        }
    }
    term_width = shutil.get_terminal_size().columns
    box_width = min(term_width - 4, 100)
    pad = 2

    def center_line(line):
        return f"║ {line.center(box_width - 4)} ║"

    def section_title(title):
        return f"{ANSI.BOLD}{ANSI.CYAN}{title}:{ANSI.RESET}"

    def line(label, value):
        return f"{ANSI.BOLD}{label:<28}:{ANSI.RESET} {value}"
    import re
    ANSI_REGEX = re.compile(r"\x1b\[[0-9;]*m")

    def visual_len(s):
        return len(ANSI_REGEX.sub("", s))    
    
    def ansi_center(s, width):
        visual = visual_len(s)
        total_pad = width - visual
        left = total_pad // 2
        right = total_pad - left
        return f"{' ' * left}{s}{' ' * right}"

    import os
    hashwarn = ""
    trusted_hash = os.getenv("PYDEP_TRUSTED_HASH")
    if trusted_hash:
        hashwarn = f"{ANSI.RED} WARNING: USING TRUSTED HASH | Last 10: [{trusted_hash[-10:]}]{ANSI.RESET}        "

    lines = [
        "═" * box_width,
        center_line(f"PYDEPGUARD ZERO TRUST RUNTIME | STATUS: {data['status'].upper()}"),
        center_line(f"{data['timestamp']} | {data['uuid']}"),
        center_line(ansi_center(hashwarn, box_width - 4) if hashwarn else ""),
        "═" * box_width,
        f"{section_title('RUNTIME')}",
        line("Uptime (sec)", data["runtime"]["uptime_sec"]),
        line("Runtime UUID", data["runtime"]["uuid"]),
        line("Package", data["runtime"]["package"]),
        line("Version", data["runtime"]["version"]),
        line("Fingerprint Hash", data["runtime"]["fingerprint_hash"]),
        f"{section_title('SYSTEM')}",
        line("Hostname", data["system"]["hostname"]),
        line("OS", data["system"]["os"]),
        line("Release", data["system"]["os_release"]),
        line("Version", data["system"]["os_version"]),
        line("Arch", data["system"]["arch"]),
        line("Platform", data["system"]["platform"]),
        line("User", data["system"]["user"]),
        line("Processor", data["system"]["cpu"]["processor"]),
        line("CPU Count", str(data["system"]["cpu"]["count"])),
        line("Memory (GB)", str(data["system"]["memory"]["gb"])),
        line("Memory (GiB)", str(data["system"]["memory"]["gib"])),
        f"{section_title('PYTHON')}",
        line("Version", data["python"]["version"]),
        line("Build", " ".join(data["python"]["build"])),
        line("Compiler", data["python"]["compiler"]),
        line("Python Path", data["python"]["abs_path"]),
        line("Interpreter Hash", data["python"]["interpreter_hash"]),
        line("CWD", data["python"]["cwd"]),
        line("Executable", data["python"]["executable"]),
        "═" * box_width,
    ]
    return "\n".join(lines)

def flatten_dict(d, parent_key='', sep='.'):
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)

