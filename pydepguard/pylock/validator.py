import importlib.metadata
import subprocess
from .package_handler import ensure_package, install_package

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

def validate_environment(lockfile, *, strict=True, interactive=True, on_error='abort', fix_missing=False):
    if not isinstance(lockfile, dict) or 'deps' not in lockfile:
        raise ValueError("[pylock] Invalid lockfile format: 'deps' key missing")

    for dep, info in lockfile['deps'].items():
        try:
            result = check_package_availability(dep, info.get('version'))
        except Exception as e:
            print(f"[pylock] Error checking {dep}: {e}")
            if on_error == 'abort':
                raise RuntimeError(f"[pylock] Dependency check failed for {dep}")
            elif on_error == 'warn':
                continue
            else: 
                continue

        if not result['available']:
            msg = f"[pylock] Missing required package: {dep}"
            if fix_missing:
                try:
                    ensure_package(dep, info.get('version'))
                    continue
                except Exception as e:
                    print(f"[pylock.WARN] Auto-install failed: {e}")
            if on_error == 'abort': 
                raise RuntimeError(msg)
            elif on_error == 'warn':
                print(f"WARNING: {msg}")
                continue
            else:
                continue

        if strict and not result['version_matches']:
            msg = (f"[pylock] Version mismatch for {dep}: "
                   f"expected {info['version']}, found {result['version']}")
            print(msg)
            if interactive:
                try:
                    response = input("Continue anyway? (yes/no): ")
                except KeyboardInterrupt:
                    print("\n[pylock] Aborted by user.")
                    raise SystemExit(130)
                if response.strip().lower() != 'yes':
                    raise RuntimeError("[pylock] Validation aborted due to version mismatch.")
            else:
                if on_error == 'abort':
                    raise RuntimeError("[pylock] Validation failed due to version mismatch.")
                elif on_error == 'warn': 
                    print(f"WARNING: {msg}")
                    continue
                else: 
                    continue

    print("[pylock] Environment validation passed.")