import builtins
import importlib
import subprocess
import sys
import urllib.request
import runpy
import importlib.util
import importlib.abc
import inspect
from pydepguardnext.api.log.logit import logit

_original_import = builtins.__import__
_original_importlib_import_module = importlib.import_module

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
    try:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/json", timeout=2) as resp:
            return resp.status == 200
    except Exception:
        return False


def _is_probably_real_package(name: str) -> bool:
    return (
        name not in sys.builtin_module_names
        and not name.startswith("_")
        and "." not in name  # submodules
        and name.isidentifier()
    )


class AutoInstallFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        sys.meta_path = [f for f in sys.meta_path if not isinstance(f, AutoInstallFinder)]
        try:
            return importlib.util.find_spec(fullname)
        except ModuleNotFoundError:
            if not _is_probably_real_package(fullname):
                raise
            try:
                logit(f"Auto-installing: {fullname}", "i")
                subprocess.check_call([sys.executable, "-m", "pip", "install", fullname], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return importlib.util.find_spec(fullname)
            except Exception as e:
                logit(f"Failed to auto-install {fullname}: {e}", "e")
                raise
        finally:
            sys.meta_path.insert(0, self)


def _patched_import(name, globals=None, locals=None, fromlist=(), level=0):
    try:
        return _original_import(name, globals, locals, fromlist, level)
    except ImportError as e:
        top = name.split(".")[0]

        if not _is_probably_real_package(top):
            raise

        if not _called_from_user_script():
            logit(f"Skipping auto-install for {top} (not from user script)", "d")
            raise

        pkg_name = _known_aliases.get(top, top)
        if not _package_exists(pkg_name):
            logit(f"Package '{pkg_name}' not found on PyPI, skipping install", "w")
            raise

        try:
            logit(f"__import__ fallback: attempting to install {pkg_name}", "i")
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError as pip_fail:
            logit(f"Installation of {pkg_name} failed: {pip_fail}", "w")
            raise e  
        return _original_import(name, globals, locals, fromlist, level)


def _patched_importlib_import_module(name, package=None):
    try:
        return _original_importlib_import_module(name, package)
    except ImportError:
        top = name.split(".")[0]
        pkg_name = _known_aliases.get(top, top)
        if _is_probably_real_package(pkg_name) and _package_exists(pkg_name):
            logit(f"Auto-installing missing dependency: {pkg_name}", "i")
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return _original_importlib_import_module(name, package)
        logit(f"Package '{top}' not found on PyPI, skipping install", "w")
        raise


def patch_all_import_hooks():
    builtins.__import__ = _patched_import
    importlib.import_module = _patched_importlib_import_module
    if not any(isinstance(f, AutoInstallFinder) for f in sys.meta_path):
        sys.meta_path.insert(0, AutoInstallFinder())


def install_missing_and_retry(script_path: str):
    patch_all_import_hooks()
    return runpy.run_path(script_path)
