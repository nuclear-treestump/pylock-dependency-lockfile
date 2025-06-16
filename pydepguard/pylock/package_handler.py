import subprocess
import sys
import importlib.metadata
import importlib.resources as resources
import json
import re
from .cache import KNOWN_DEP_MAP



def guess_distribution_name(module_name: str):
    for dist in importlib.metadata.distributions():
        try:
            top_levels = dist.read_text("top_level.txt")
            if top_levels:
                names = [line.strip() for line in top_levels.splitlines()]
                if module_name in names:
                    return dist.metadata["Name"]
        except Exception:
            continue
    return None


def install_package(package: str, version: str = None, _is_retry=False):

    mapped = KNOWN_DEP_MAP.get(package.lower())

    if mapped and mapped.lower() != package.lower():
        print(f"[pylock] Using mapped pip name: {package} → {mapped}")
        package = mapped
        version = ""

    if version == "unknown":
        version = ""

    pkg = f"{package}=={version}" if version else package

    print(f"[pylock] Installing {pkg} ...")

    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", pkg],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if result.returncode == 0:
        version = extract_installed_version(result.stdout, package)

        print(f"[pylock] Installed {pkg} ({version}) successfully.")
        return True

    stderr = result.stderr.decode().strip()
    print(f"[pylock] Installation error: {stderr}")


    if not _is_retry:
        guessed = guess_distribution_name(package)
        if guessed and guessed.lower() != package.lower():
            print(f"[pylock] Trying again with guessed pip name: {guessed}")
            return install_package(guessed, version, _is_retry=True)

    raise RuntimeError(f"[pylock] Failed to install {package}")


def ensure_package(module_name: str, version: str = None):
    try:
        __import__(module_name)
        return True
    except ImportError:
        print(f"[pylock] {module_name} not found. Attempting install...")
        return install_package(module_name, version)

def load_known_depmap():
    try:
        with resources.files("pydepguard.pylock").joinpath("known_deps.pydepcache").open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[pylock.WARN] Failed to load known dependency map: {e}")
        return {}
    

def extract_installed_version(stdout: bytes, package_name: str) -> str | None:
    text = stdout.decode("utf-8")
    pattern = rf"Successfully installed {re.escape(package_name)}-([\w\.\-]+)"
    match = re.search(pattern, text)
    if match:
        return match.group(1)
    return None