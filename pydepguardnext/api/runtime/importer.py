import builtins
import importlib
from importlib import metadata
import subprocess
import sys
import urllib.request
import runpy
import importlib.util
import importlib.abc
import inspect
import time
import json
from pydepguardnext import PyDepBullshitDetectionError
from pydepguardnext.api.log.logit import logit
from typing import Tuple
import hashlib
from pathlib import Path
from .integrity import INTEGRITY_CHECK, run_integrity_check, jit_check

JIT_INTEGRITY_CHECK = jit_check
_original_import = builtins.__import__
_original_importlib_import_module = importlib.import_module
_global_timecheck = 0
_current_modules = metadata.distributions()

logslug = "api.runtime.importer"

_known_aliases = {
    "PIL": "Pillow",
    "cv2": "opencv-python",
    "skimage": "scikit-image",
    "sklearn": "scikit-learn",
    "yaml": "pyyaml",
    "bs4": "beautifulsoup4",
    "Crypto": "pycryptodome",
    "Image": "Pillow",
    "lxml.etree": "lxml",  
} 

_known_skip_pypi_modules = {
    "cwd",
    "_subprocess",
    "_elementtree",
    "grp",
    "pwd",
    "compression",
    "tests"
}


# TODO:Replace with user-controlled override in the future


DEBUG_IMPORTS = True


def _called_from_user_script():
    for frame in inspect.stack():
        f = frame.filename
        if f.endswith("runpy.py") or "site-packages" in f:
            continue
        if f.endswith(".py") and not f.startswith(sys.prefix):
            return True
    return False

# This will be used later to log import attempts and for debugging purposes.
# It has been exempted from coverage since it is not part of the main functionality.

def _log(name):   #pragma: no cover
    if DEBUG_IMPORTS:
        print(f"[HOOK] Trying import: {name}")

def _package_exists(name: str) -> bool:
    check_time = time.time()
    try:
        if name in _known_skip_pypi_modules:
            logit(f"Skipping PyPI check for known module: {name}, as module does not exist.", "i", source=f"{logslug}.{_package_exists.__name__}")
            return False
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/json", timeout=2) as resp:
            logit(f"Time taken to check package {name}: {time.time() - check_time:.2f} seconds", "i", source=f"{logslug}.{_package_exists.__name__}")
            return resp.status == 200
    except Exception:
        logit(f"Time taken to check package {name}: {time.time() - check_time:.2f} seconds", "i", source=f"{logslug}.{_package_exists.__name__}")
        logit(f"Package '{name}' not found on PyPI", "e", source=f"{logslug}.{_package_exists.__name__}")
        return False


def _is_probably_real_package(name: str) -> Tuple[bool, str]:
    name = name.lower()
    match name:
        case name if name in sys.builtin_module_names:
            return False, "builtin"
        case name if name in _known_skip_pypi_modules:
            return False, "skip"
        case name if name.startswith("_"):
            return False, "private"
        case name if not name.isidentifier():
            return False, "invalid"
        case _:
            return True, "valid"



class AutoInstallFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        sys.meta_path = [f for f in sys.meta_path if not isinstance(f, AutoInstallFinder)]
        try:
            return importlib.util.find_spec(fullname)
        except ModuleNotFoundError:
            logit(f"Caught ModuleNotFoundError for {fullname}, attempting auto-install at {time.time() - _global_timecheck} seconds", "w", source=f"{logslug}.{type(self).__name__}")
            is_real, _ = _is_probably_real_package(fullname)
            if not is_real:
                raise
            try:
                if id(_patched_import) != INTEGRITY_CHECK["importer._patched_import"]:
                    logit(f"ID MISMATCH: _patched_import has been modified, aborting auto-install", "f", source=f"{logslug}.{type(self).__name__}")
                    raise PyDepBullshitDetectionError(expected=INTEGRITY_CHECK["importer._patched_import"], found=id(_patched_import))
                logit(f"Auto-installing: {fullname}", "i", source=f"{logslug}.{type(self).__name__}")
                logit(f"Installing {fullname} ...", "i", source=f"{logslug}.{type(self).__name__}")
                install_time = time.time()
                subprocess.check_call([sys.executable, "-m", "pip", "install", fullname, "--progress-bar", "off"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logit(f"Installed {fullname} successfully in {time.time() - install_time:.2f} seconds", "i", source=f"{logslug}.{type(self).__name__}")
                return importlib.util.find_spec(fullname)
            except Exception as e:
                logit(f"Failed to auto-install {fullname}: {e}", "e", source=f"{logslug}.{type(self).__name__}")
                raise
        finally:
            sys.meta_path.insert(0, self)


def _patched_import(name, globals=None, locals=None, fromlist=(), level=0):
    try:
        return _original_import(name, globals, locals, fromlist, level)
    except ImportError as e:
        logit(f"[patched_import] Caught ImportError for {name}, attempting auto-install at {time.time() - _global_timecheck} seconds", "w", source=f"{logslug}.{_patched_import.__name__}")
        top = name.split(".")[0]
        logit(f"Top-level module: {top}", "d", source=f"{logslug}.{_patched_import.__name__}")
        if top in [dist.metadata["Name"].lower() for dist in _current_modules]:
            logit(f"Package '{top}' already installed, skipping auto-install", "d", source=f"{logslug}.{_patched_import.__name__}")
            return _original_import(name, globals, locals, fromlist, level)

        if top in _known_skip_pypi_modules:
            logit(f"Skipping auto-install for {top} (known skip module)", "d", source=f"{logslug}.{_patched_import.__name__}")
            raise

        is_real, reason = _is_probably_real_package(top)
        if not is_real:
            logit(f"Skipping auto-install for {top} (not a real package) Reason: {reason}", "d", source=f"{logslug}.{_patched_import.__name__}")
            raise

        if not _called_from_user_script():
            logit(f"Skipping auto-install for {top} (not from user script)", "d", source=f"{logslug}.{_patched_import.__name__}")
            raise

        pkg_name = _known_aliases.get(top, top)
        if not _package_exists(pkg_name):
            logit(f"Package '{pkg_name}' not found on PyPI, skipping install", "w", source=f"{logslug}.{_patched_import.__name__}")
            raise

        try:
            if id(_patched_import) != INTEGRITY_CHECK["importer._patched_import"]:
                logit(f"ID MISMATCH: _patched_import has been modified, aborting auto-install", "f", source=f"{logslug}.{_patched_import.__name__}")
                raise PyDepBullshitDetectionError(expected=INTEGRITY_CHECK["importer._patched_import"], found=id(_patched_import))
            logit(f"__import__ fallback: attempting to install {pkg_name}", "i", source=f"{logslug}.{_patched_import.__name__}")
            logit(f"Installing {pkg_name} ...", "i", source=f"{logslug}.{_patched_import.__name__}")
            install_time = time.time()
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg_name, "--progress-bar", "off"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logit(f"Installed {pkg_name} successfully in {time.time() - install_time:.2f} seconds", "i", source=f"{logslug}.{_patched_import.__name__}")
        except subprocess.CalledProcessError as pip_fail:
            logit(f"Installation of {pkg_name} failed: {pip_fail}", "w", source=f"{logslug}.{_patched_import.__name__}")
            raise pip_fail
        return _original_import(name, globals, locals, fromlist, level)


def _patched_importlib_import_module(name, package=None):
    try:
        return _original_importlib_import_module(name, package)
    except ImportError:
        logit(f"[patched_import_module] Caught ImportError for {name}, attempting auto-install at {time.time() - _global_timecheck} seconds", "i", source=f"{logslug}.{_patched_importlib_import_module.__name__}")
        top = name.split(".")[0]
        pkg_name = _known_aliases.get(top, top)
        is_real, reason = _is_probably_real_package(top)
        if top in _known_skip_pypi_modules:
            logit(f"Skipping auto-install for {pkg_name} (known skip module)", "d", source=f"{logslug}.{_patched_importlib_import_module.__name__}")
            raise
        if is_real:
            if _package_exists(pkg_name):
                if id(_patched_importlib_import_module) != INTEGRITY_CHECK["importer._patched_importlib_import_module"]:
                    logit(f"ID MISMATCH: _patched_importlib_import_module has been modified, aborting auto-install", "f", source=f"{logslug}.{_patched_importlib_import_module.__name__}")
                    raise PyDepBullshitDetectionError(expected=INTEGRITY_CHECK["importer._patched_importlib_import_module"], found=id(_patched_importlib_import_module))
                logit(f"Auto-installing missing dependency: {pkg_name}", "i", source=f"{logslug}.{_patched_importlib_import_module.__name__}")
                logit(f"Installing {pkg_name} ...", "i", source=f"{logslug}.{_patched_importlib_import_module.__name__}")
                install_time = time.time()
                subprocess.check_call([sys.executable, "-m", "pip", "install", pkg_name, "--progress-bar", "off"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logit(f"Installed {pkg_name} in {time.time() - install_time:.2f} seconds", "i", source=f"{logslug}.{_patched_importlib_import_module.__name__}")
                return _original_importlib_import_module(name, package)
        else:
            logit(f"Skipping auto-install for {top} Reason: {reason}", "d", source=f"{logslug}.{_patched_importlib_import_module.__name__}")
        logit(f"Package '{top}' not found on PyPI, skipping install", "w", source=f"{logslug}.{_patched_importlib_import_module.__name__}")
        raise


def patch_all_import_hooks():
    builtins.__import__ = _patched_import
    importlib.import_module = _patched_importlib_import_module
    if not any(isinstance(f, AutoInstallFinder) for f in sys.meta_path):
        sys.meta_path.insert(0, AutoInstallFinder())


def install_missing_and_retry(script_path: str, timecheck=None, cached=False):
    global _global_timecheck
    _global_timecheck = timecheck or time.time()
    if not cached:
        patch_all_import_hooks()
    result = runpy.run_path(script_path)
    dists = metadata.distributions()
    dist_list = list()
    for dist in dists:
        dist_list.append({
            "name": dist.metadata["Name"],
            "version": dist.version,
            "summary": dist.metadata.get("Summary", ""),
            "homepage": dist.metadata.get("Home-page", ""),
            "author": dist.metadata.get("Author", ""),
            "license": dist.metadata.get("License", ""),
        })
    return result, dist_list

