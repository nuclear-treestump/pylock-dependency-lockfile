import os
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import List, Optional
from pydepguardnext.api.log.logit import logit
import builtins
import types
import sys
from types import MappingProxyType 

logslug = "api.runtime.airjail"
_sandbox_enabled = False
_maximum_security_details = {}
_maximum_security_enabled = False

def _raise_ctypes_blocked(*args, **kwargs):
    raise RuntimeError("ctypes is blocked unless --need-ctypes is enabled")

def block_ctypes():
    blocked_ctypes = types.ModuleType("ctypes")
    setattr(blocked_ctypes, "CDLL", _raise_ctypes_blocked)

    sys.modules["ctypes"] = blocked_ctypes
    builtins.__import__ = _wrap_import(builtins.__import__)

def _wrap_import(orig_import):
    def wrapped(name, *args, **kwargs):
        if name.startswith("ctypes"):
            raise ImportError("ctypes blocked unless --need-ctypes is provided")
        return orig_import(name, *args, **kwargs)
    return wrapped


def enable_sandbox_open():
    global _sandbox_enabled
    if _sandbox_enabled:
        return

    import builtins
    _real_open = builtins.open

    def sandbox_open(path, *args, **kwargs):
        from pathlib import Path
        root = Path(".").resolve()
        try:
            target = Path(path).resolve()
            if not str(target).startswith(str(root)):
                raise PermissionError(f"Access denied outside of fakeroot: {target}")
        except Exception as e:
            raise PermissionError(f"Access denied: {e}")
        return _real_open(path, *args, **kwargs)

    builtins.open = sandbox_open
    _sandbox_enabled = True
    logit("sandbox_open is now active", "i")

def disable_network_access():
    import socket
    import builtins

    def blocked_socket(*args, **kwargs):
        raise RuntimeError("Network access is blocked in this environment")

    socket.socket = blocked_socket
    builtins.__import__ = _wrap_import(builtins.__import__)
    logit("Network access has been disabled", "i")

def disable_file_write():
    import builtins
    import os

    def blocked_open(*args, **kwargs):
        if 'w' in args[0] or 'a' in args[0] or 'x' in args[0]:
            raise PermissionError("File write operations are blocked in this environment")
        return builtins.open(*args, **kwargs)

    builtins.open = blocked_open
    logit("File write operations have been disabled", "i")

def disable_urllib_requests():
    import urllib.request
    import urllib.error

    def blocked_urlopen(*args, **kwargs):
        raise RuntimeError("Network access is blocked in this environment")

    urllib.request.urlopen = blocked_urlopen
    urllib.error.URLError = RuntimeError
    logit("urllib requests have been disabled", "i")

def disable_socket_access():
    import socket
    import builtins

    def blocked_socket(*args, **kwargs):
        raise RuntimeError("Socket access is blocked in this environment")

    socket.socket = blocked_socket
    builtins.__import__ = _wrap_import(builtins.__import__)
    logit("Socket access has been disabled", "i")

def shadow_eval(code: str, globals=None, locals=None):
    if globals is None:
        globals = {}
    if locals is None:
        locals = {}

    if _maximum_security_details["_maximum_security_enabled"]:
        logit(f"CODE RUN DETECTED: {code}", "w", source=f"{logslug}.{__name__}")
        raise RuntimeError("Maximum security mode is enabled, code execution is blocked.")
    
    
    



    return eval(code, globals, locals)

def patch_environment_to_venv(venv_path: Path):
    import sys
    bin_dir = venv_path / ("Scripts" if os.name == "nt" else "bin")
    python_path = bin_dir / ("python.exe" if os.name == "nt" else "python3")

    os.environ["PATH"] = os.pathsep.join([str(bin_dir)])
    os.environ["VIRTUAL_ENV"] = str(venv_path)
    sys.executable = str(python_path)

def maximum_security():
    block_ctypes()
    enable_sandbox_open()
    disable_file_write()
    disable_network_access()
    disable_urllib_requests()
    disable_socket_access()
    logit("Maximum security mode is now active. Enjoy your stay!", "i", source=f"{logslug}.{__name__}")
    global _maximum_security_enabled
    _maximum_security_enabled = True
    _maximum_security_enabled = MappingProxyType({
        "sandbox_open": _sandbox_enabled,
        "ctypes_blocked": True,
        "network_access_blocked": True,
        "file_write_blocked": True,
        "urllib_requests_blocked": True,
        "socket_access_blocked": True,
        "_maximum_security_enabled": True
    })

def prepare_fakeroot(
    script_path: Path,
    include_files: Optional[List[Path]] = None,
    persist: bool = False,
    hash_suffix: str = "",
    base_dir: Optional[Path] = None,
    enable_sandbox: bool = False,
) -> Path:
    if include_files is None:
        include_files = []

    base_dir = base_dir or Path(".pydepguard_venvs")
    base_dir.mkdir(parents=True, exist_ok=True)

    tag = "persist" if persist else uuid.uuid4().hex[:8]
    fakeroot_path = base_dir / f"fakeroot_{hash_suffix}_{tag}"
    app_dir = fakeroot_path / "app"

    if not persist:
        shutil.rmtree(fakeroot_path, ignore_errors=True)

    app_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(script_path, app_dir / "main.py")

    for file in include_files:
        if file.exists():
            dest = app_dir / file.name
            shutil.copy2(file, dest)
    patch_environment_to_venv(fakeroot_path)
    if enable_sandbox:
        enable_sandbox_open()

    logit(f"Prepared fakeroot at {fakeroot_path}", "i", source=f"{logslug}.{prepare_fakeroot.__name__}")
    return app_dir