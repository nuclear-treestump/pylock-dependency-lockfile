import importlib.metadata
import subprocess
from packaging.version import Version, InvalidVersion

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

def validate_environment(lockfile):
    for dep, info in lockfile['deps'].items():
        result = check_package_availability(dep, info.get('version'))
        if not result['available']:
            raise RuntimeError(f"Missing required package: {dep}")
        if not result['version_matches']:
            print(f"Version mismatch for {dep}: expected {info['version']}, found {result['version']}")
            response = input("Continue anyway? (yes/no): ")
            if response.lower() != 'yes':
                raise RuntimeError("Aborted by user.")