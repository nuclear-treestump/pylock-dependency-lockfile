import os
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import List, Optional
from pydepguardnext.api.log.logit import logit

_sandbox_enabled = False

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

def patch_environment_to_venv(venv_path: Path):
    import sys
    bin_dir = venv_path / ("Scripts" if os.name == "nt" else "bin")
    python_path = bin_dir / ("python.exe" if os.name == "nt" else "python3")

    os.environ["PATH"] = os.pathsep.join([str(bin_dir)])
    os.environ["VIRTUAL_ENV"] = str(venv_path)
    sys.executable = str(python_path)

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

    logit(f"Prepared fakeroot at {fakeroot_path}", "i")
    return app_dir