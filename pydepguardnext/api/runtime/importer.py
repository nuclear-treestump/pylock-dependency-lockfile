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
from collections import defaultdict

JIT_INTEGRITY_CHECK = jit_check
_original_import = builtins.__import__
_original_importlib_import_module = importlib.import_module
_global_timecheck = 0
_current_modules = metadata.distributions()
_timing = float()
_urltiming = float()
_timepermodule = defaultdict(list)


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

_blocklist = {
    "pip",
    "setuptools",
    "wheel",
    "build",
    "twine",
}

_whitelist = set()
def _preload_lists():
    from os import getenv
    global _whitelist, _blocklist, _known_aliases, _known_skip_pypi_modules
    _whitelist.add("pydepguardnext")
    _whitelist.add("pydepguard")
    whitelist_temp = getenv("PYDEPGUARD_WHITELIST", "")
    _whitelist.update(whitelist_temp.split(","))
    _blocklist_temp = getenv("PYDEPGUARD_BLOCKLIST", "")
    _blocklist.update(_blocklist_temp.split(","))
    aliases_temp = getenv("PYDEPGUARD_ALIASES", "")
    for alias_pair in aliases_temp.split(","):
        if ":" in alias_pair:
            src, dst = alias_pair.split(":", 1)
            _known_aliases[src.strip()] = dst.strip()
    skip_temp = getenv("PYDEPGUARD_SKIP_PYPI", "")
    _known_skip_pypi_modules.update(skip_temp.split(","))
    if "pydepguardnext" in _whitelist and "pydepguard" in _whitelist and len(_whitelist) > 2 and getenv("PYDEPGUARD_WHITELIST", "") != "":
        _blocklist = {"all"}
        # Setting whitelist assumes block all except those in whitelist
        # This is the expected behavior as using a whitelist activates implicit deny.
        # PyDepGuard and PyDepGuardNext are always whitelisted to ensure core functionality.
        # THIS BLOCKS ALIASES AND SKIP LISTS AS WELL
    logit(f"Whitelist: {_whitelist}", "d", source=f"{logslug}.{_preload_lists.__name__}")
    logit(f"Blocklist: {_blocklist}", "d", source=f"{logslug}.{_preload_lists.__name__}")
    logit(f"Known Aliases: {_known_aliases}", "d", source=f"{logslug}.{_preload_lists.__name__}")
    logit(f"Known Skip PyPI Modules: {_known_skip_pypi_modules}", "d", source=f"{logslug}.{_preload_lists.__name__}")

    


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
    global _urltiming
    global _timepermodule
    try:
        if name in _blocklist or "all" in _blocklist:
            logit(f"Skipping PyPI check for blocked package: {name}", "i", source=f"{logslug}.{_package_exists.__name__}")
            return False
        if name in _whitelist:
            logit(f"Skipping PyPI check for whitelisted package: {name}", "i", source=f"{logslug}.{_package_exists.__name__}")
            return True
        if name in _known_aliases:
            logit(f"Skipping PyPI check for known alias: {name} as it is an alias for {_known_aliases[name]}.", "i", source=f"{logslug}.{_package_exists.__name__}")
            return True
        if name in _known_skip_pypi_modules:
            logit(f"Skipping PyPI check for known module: {name}, as module does not exist.", "i", source=f"{logslug}.{_package_exists.__name__}")
            return False
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/json", timeout=2) as resp:
            _urltime = time.time() - check_time
            _urltiming += _urltime
            logit(f"Time taken to check package {name}: {_urltime:.2f} seconds", "i", source=f"{logslug}.{_package_exists.__name__}")
            return resp.status == 200
    except Exception:
        logit(f"Time taken to check package {name}: {time.time() - check_time:.2f} seconds", "i", source=f"{logslug}.{_package_exists.__name__}")
        logit(f"Package '{name}' not found on PyPI", "e", source=f"{logslug}.{_package_exists.__name__}")
        return False


def _is_probably_real_package(name: str) -> Tuple[bool, str]:
    name = name.lower()
    match name:
        case name if name in _blocklist:
            return False, "blocklist"
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
                global _timing
                _install_time = time.time() - install_time
                _timing += _install_time
                logit(f"Installed {fullname} successfully in {_install_time:.2f} seconds", "i", source=f"{logslug}.{type(self).__name__}")
                _timepermodule[fullname].append(_install_time)  
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
        if '.' in name and name not in _known_aliases:
            logit(f"Skipping auto-install for submodule: {name}", "i", source=f"{logslug}.{_patched_import.__name__}")
            raise e
        top = name.split(".")[0]
        if name in _blocklist:
            logit(f"Skipping auto-install for blocked package: {name}", "i", source=f"{logslug}.{_patched_import.__name__}")
            raise e
        logit(f"Top-level module: {top}", "d", source=f"{logslug}.{_patched_import.__name__}")
        if top in _known_skip_pypi_modules:
            logit(f"Skipping auto-install for {top} (known skip module)", "i", source=f"{logslug}.{_patched_import.__name__}")
            raise
        if top in [dist.metadata["Name"].lower() for dist in _current_modules]:
            logit(f"Package '{top}' already installed, skipping auto-install", "i", source=f"{logslug}.{_patched_import.__name__}")
            return _original_import(name, globals, locals, fromlist, level)
        
        _alias_check = False
        is_real = False
        if top in _known_aliases:
            logit(f"Top-level module: {top} mapped to alias: {_known_aliases[top]}", "i", source=f"{logslug}.{_patched_import.__name__}")
            top = _known_aliases[top]
            _alias_check = True
            is_real = True
        if not _alias_check:
            is_real, reason = _is_probably_real_package(top)
        if not is_real:
            logit(f"Skipping auto-install for {top} (not a real package) Reason: {reason}", "i", source=f"{logslug}.{_patched_import.__name__}")
            raise

        if not _called_from_user_script():
            logit(f"Skipping auto-install for {top} (not from user script)", "i", source=f"{logslug}.{_patched_import.__name__}")
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
            global _timing, _timepermodule
            _install_time = time.time() - install_time
            _timing = _timing + (_install_time)
            logit(f"Installed {pkg_name} successfully in {_install_time:.2f} seconds", "i", source=f"{logslug}.{_patched_import.__name__}")        
            _timepermodule[pkg_name].append(_install_time)    
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
        if name in _blocklist:
            logit(f"Skipping auto-install for blocked package: {name}", "i", source=f"{logslug}.{_patched_importlib_import_module.__name__}")
            raise
        if '.' in name and name not in _known_aliases:
            logit(f"Skipping auto-install for submodule: {name}", "i", source=f"{logslug}.{_patched_importlib_import_module.__name__}")
            raise
        skip_check = False
        if top in _known_aliases:
            pkg_name = _known_aliases[top]
            logit(f"Top-level module: {top} mapped to alias: {pkg_name}", "i", source=f"{logslug}.{_patched_importlib_import_module.__name__}")
            is_real = True
            skip_check = True
        if top in _known_skip_pypi_modules:
            logit(f"Skipping auto-install for {top} (known skip module)", "i", source=f"{logslug}.{_patched_importlib_import_module.__name__}")
            raise
        is_real = False
        if not skip_check:
            is_real, reason = _is_probably_real_package(top)
        if is_real:
            if _package_exists(top):
                if id(_patched_importlib_import_module) != INTEGRITY_CHECK["importer._patched_importlib_import_module"]:
                    logit(f"ID MISMATCH: _patched_importlib_import_module has been modified, aborting auto-install", "f", source=f"{logslug}.{_patched_importlib_import_module.__name__}")
                    raise PyDepBullshitDetectionError(expected=INTEGRITY_CHECK["importer._patched_importlib_import_module"], found=id(_patched_importlib_import_module))
                logit(f"Installing {top} ...", "i", source=f"{logslug}.{_patched_importlib_import_module.__name__}")
                install_time = time.time()
                subprocess.check_call([sys.executable, "-m", "pip", "install", top, "--progress-bar", "off"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                global _timing, _timepermodule
                _install_time = time.time() - install_time
                _timing = _timing + (_install_time)
                _timepermodule[top].append(_install_time)    
                logit(f"Installed {top} in {_install_time:.2f} seconds", "i", source=f"{logslug}.{_patched_importlib_import_module.__name__}")
                return _original_importlib_import_module(name, package)
        else:
            logit(f"Skipping auto-install for {top} Reason: {reason or 'unknown'}", "d", source=f"{logslug}.{_patched_importlib_import_module.__name__}")
        logit(f"Package '{top}' not found on PyPI, skipping install", "w", source=f"{logslug}.{_patched_importlib_import_module.__name__}")
        raise


def patch_all_import_hooks():
    builtins.__import__ = _patched_import
    importlib.import_module = _patched_importlib_import_module
    if not any(isinstance(f, AutoInstallFinder) for f in sys.meta_path):
        sys.meta_path.insert(0, AutoInstallFinder())


def stats_from_import(_timepermodule):
    all_times = [t for durations in _timepermodule.values() for t in durations]
    if not all_times:
        return {}, 0.0, 0.0

    sorted_times = sorted(all_times)
    mid = len(sorted_times) // 2
    median = (
        sorted_times[mid]
        if len(sorted_times) % 2 == 1
        else (sorted_times[mid - 1] + sorted_times[mid]) / 2
    )
    average = sum(all_times) / len(all_times)

    stats = {
        pkg: {
            "total": sum(times),
            "count": len(times),
            "max": max(times),
            "min": min(times),
            "avg": sum(times) / len(times),
        }
        for pkg, times in _timepermodule.items()
    }
    return stats, median, average

def generate_import_suggestions(stats: dict, median: float, average: float, threshold_factor: float = 2.0) -> list[str]:
    suggestions = []
    for pkg, data in stats.items():
        avg_time = data["avg"]
        if avg_time > average * threshold_factor or avg_time > median * threshold_factor:
            suggestions.append(
                f"[IMPROVEMENT] Consider prewarming '{pkg}': avg import {avg_time:.3f}s over {data['count']} loads"
            )
    return suggestions



def install_missing_and_retry(script_path: str, timecheck=None, cached=False):
    import contextlib
    import io
    global _global_timecheck, _timepermodule
    _global_timecheck = timecheck or time.time()
    if not cached:
        patch_all_import_hooks()
    from pydepguardnext import get_gtime
    from datetime import datetime 

    combined = io.StringIO()

    _preload_lists()

    prerun_details = {"obj_type": "prerun", "script_path": script_path, "time": datetime.now().isoformat(), "cached": cached, "parent_uuid": INTEGRITY_CHECK["global_.jit_check_uuid"]}
    with contextlib.redirect_stdout(combined), contextlib.redirect_stderr(combined):
        result = runpy.run_path(script_path)

    print(result)

    loglines = combined.getvalue().strip().splitlines()

    header_data = {
        "obj_type": "postrun",
        "end_time": datetime.now().isoformat(),
        "prerun_details": prerun_details,
        "script_path": script_path,
        "cached": cached,
        "dependencies_installed": ', '.join(_timepermodule.keys()) if _timepermodule else 'None'
    }

    loglines.insert(0, str(prerun_details))
    loglines.append(str(header_data))

    logit("\n".join(loglines), "u", source="USER_SCRIPT", redir_file="pydepguard.runtime.log")
    global _timing, _urltiming
    timeblock = {"url": _urltiming, "download": _timing}
    dists = metadata.distributions()
    dist_list = [{
        "name": dist.metadata["Name"],
        "version": dist.version,
        "summary": dist.metadata.get("Summary", ""),
        "homepage": dist.metadata.get("Home-page", ""),
        "author": dist.metadata.get("Author", ""),
        "license": dist.metadata.get("License", ""),
    } for dist in dists]
    stats, median, average = stats_from_import(_timepermodule)
    suggestions = generate_import_suggestions(stats, median, average)
    if suggestions:
        logit(f"Import suggestions: {', '.join(suggestions)}", "z", source=f"{logslug}.{install_missing_and_retry.__name__}")

    return result, dist_list, timeblock
