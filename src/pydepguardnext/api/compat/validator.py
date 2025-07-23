# pydepguardnext/api/validator.py

import importlib.metadata
import subprocess
from pydepguardnext.api.log.logit import logit

logslug = "api.compat.validator"

def resolve_installed_package_info(package_name: str) -> dict:
    try:
        version = importlib.metadata.version(package_name)
        return {'available': True, 'version': version, 'source': 'importlib'}
    except importlib.metadata.PackageNotFoundError:
        pass

    result = subprocess.run(['pip', 'show', package_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        output = result.stdout.decode('utf-8')
        version = None
        for line in output.splitlines():
            if line.lower().startswith("version:"):
                version = line.split(": ", 1)[1].strip()
                break
        return {'available': True, 'version': version, 'source': 'pip_show'}

    return {'available': False, 'version': None, 'source': 'none'}

def check_package_availability(package, expected_version=None):
    info = resolve_installed_package_info(package)

    return {
        'available': info['available'],
        'version_matches': (expected_version is None or expected_version == info['version']),
        'version': info['version'],
        'source': info['source']
    }

def validate_environment_legacy(lockfile, *, strict=True, interactive=True, on_error='abort'):
    """
    DEPRECATED: Legacy lockfile validator.
    Supports `.pylock`-style lockfiles with flat dependency version keys.

    This will be removed in v6.0.0. It is retained for compatibility with PDG 3.x series only.
    Future versions of PyDepGuard will rely on .pdgpolicy runtime manifests.

    Args:
        lockfile (dict): Loaded `.pylock` file.
        strict (bool): Enforce exact version match.
        interactive (bool): Prompt user for mismatches.
        on_error (str): One of 'abort', 'warn', or 'skip'.
    """
    if not isinstance(lockfile, dict) or 'deps' not in lockfile:
        raise ValueError("[COMPAT] Invalid lockfile format: 'deps' key missing")

    for dep, info in lockfile['deps'].items():
        try:
            result = check_package_availability(dep, info.get('version'))
        except Exception as e:
            logit(f"[COMPAT] Error checking {dep}: {e}", "e", source=f"{logslug}.{validate_environment_legacy.__name__}")
            if on_error == 'abort':
                raise RuntimeError(f"[COMPAT] Dependency check failed for {dep}")
            elif on_error == 'warn':
                continue
            else:
                continue

        if not result['available']:
            msg = f"[COMPAT] Missing required package: {dep}"
            if on_error == 'abort':
                raise RuntimeError(msg)
            elif on_error == 'warn':
                logit(f"WARNING: {msg}", "w", source=f"{logslug}.{validate_environment_legacy.__name__}")
                continue
            else:
                continue

        if strict and not result['version_matches']:
            msg = (f"[COMPAT] Version mismatch for {dep}: "
                   f"expected {info['version']}, found {result['version']}")
            logit(msg, "w", source=f"{logslug}.{validate_environment_legacy.__name__}")
            if interactive:
                try:
                    response = input("Continue anyway? (yes/no): ")
                except KeyboardInterrupt:
                    logit("\n[COMPAT] Aborted by user.", "e", source=f"{logslug}.{validate_environment_legacy.__name__}")
                    raise SystemExit(130)
                if response.strip().lower() != 'yes':
                    raise RuntimeError("[COMPAT] Validation aborted due to version mismatch.")
            else:
                if on_error == 'abort':
                    raise RuntimeError("[COMPAT] Validation failed due to version mismatch.")
                elif on_error == 'warn':
                    logit(f"WARNING: {msg}", "w", source=f"{logslug}.{validate_environment_legacy.__name__}")
                    continue
                else:
                    continue

    logit("[COMPAT] Environment validation passed.", "i", source=f"{logslug}.{validate_environment_legacy.__name__}")
