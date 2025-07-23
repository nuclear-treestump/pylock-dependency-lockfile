from pathlib import Path
import inspect
import sys

from pydepguardnext.bootstrap.state import has_boot_run

def enforce_api_gate(allowed_subpath="standalone"):
    if has_boot_run():
        return

    frame = inspect.stack()[1]
    module_file = frame.frame.f_globals.get("__file__")
    if not module_file:
        return  # REPL or strange context

    path = Path(module_file).resolve()
    if allowed_subpath not in [p.name for p in path.parents]:
        raise ImportError(
            f"[pydepguardnext] Secure boot not completed. Module at '{path}' is not in '{allowed_subpath}/'. API is locked."
        )