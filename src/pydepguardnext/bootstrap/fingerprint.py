import platform
import os
import sys
from pathlib import Path
from hashlib import sha256
from json import dumps

def get_module_root(package_name="pydepguardnext") -> Path | None:
    from importlib.util import find_spec
    spec = find_spec(package_name)
    if not spec or not spec.origin:
        return None
    path = Path(spec.origin).resolve()
    return path.parent if path.name == "__init__.py" else path

def sha256sum_dir(directory: Path) -> str:
    h = sha256()
    for file in sorted(directory.rglob("*.py")):
        with open(file, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
    return h.hexdigest()

def get_total_memory_gb_gib():
    system = platform.system()

    def format_output(bytes_total):
        gb = bytes_total / 1_000_000_000     # decimal gigabytes
        gib = bytes_total / (1024 ** 3)      # binary gibibytes
        return round(gb, 2), round(gib, 2)

    try:
        if system == "Windows":
            import ctypes
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]
            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
            return format_output(stat.ullTotalPhys)

        elif system == "Linux":
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])  # kB
                        return format_output(kb * 1024)

        elif system == "Darwin":
            mem_bytes = int(os.popen("sysctl -n hw.memsize").read())
            return format_output(mem_bytes)

    except Exception:
        return None, None

def hash_interpreter():
    path = Path(sys.executable).resolve(strict=False)
    h = sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def generate_system_fingerprint():
    from getpass import getuser
    from socket import gethostname

    gb, gib = get_total_memory_gb_gib()
    fingerprint = {
        "hostname": gethostname(),
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "arch": platform.machine(),
        "platform": platform.platform(),
        "user": getuser(),
        "python_version": platform.python_version(),
        "python_build": platform.python_build(),
        "python_compiler": platform.python_compiler(),
        "python_abs_path": str(Path(sys.executable).resolve(strict=False)),
        "python_interpreter_hash": hash_interpreter(),
        "executable": sys.executable,
        "cwd": os.getcwd(),
        "cpu_count": os.cpu_count(),
        "processor": platform.processor(),
        "total_memory_gb": gb,
        "total_memory_gib": gib,
    }
    return fingerprint, sha256(dumps(fingerprint, sort_keys=True).encode()).hexdigest()