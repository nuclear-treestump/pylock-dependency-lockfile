import pytest
import subprocess
import importlib.metadata
from unittest.mock import patch
from pydepguard.pylock.validator import resolve_installed_package_info, check_package_availability, validate_environment

def test_importlib_succeeds(monkeypatch):
    class FakeMetadata:
        @staticmethod
        def version(name):
            if name == "requests":
                return "2.31.0"
            raise importlib.metadata.PackageNotFoundError

    monkeypatch.setattr("importlib.metadata.version", FakeMetadata.version)

    result = resolve_installed_package_info("requests")
    assert result['available'] is True
    assert result['version'] == "2.31.0"
    assert result['source'] == "importlib"

def test_importlib_fails_pip_show_succeeds(monkeypatch):
    def fail_version(name):
        raise importlib.metadata.PackageNotFoundError

    monkeypatch.setattr("importlib.metadata.version", fail_version)

    class FakeCompletedProcess:
        def __init__(self):
            self.returncode = 0
            self.stdout = b"Name: example\nVersion: 1.2.3\n"
            self.stderr = b""

    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: FakeCompletedProcess())

    result = resolve_installed_package_info("example")
    assert result['available'] is True
    assert result['version'] == "1.2.3"
    assert result['source'] == "pip_show"

def test_pip_show_no_version(monkeypatch):
    def fail_version(name):
        raise importlib.metadata.PackageNotFoundError

    monkeypatch.setattr("importlib.metadata.version", fail_version)

    class NoVersionProcess:
        def __init__(self):
            self.returncode = 0
            self.stdout = b"Name: something\n"
            self.stderr = b""

    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: NoVersionProcess())

    result = resolve_installed_package_info("something")
    assert result['available'] is True
    assert result['version'] is None
    assert result['source'] == "pip_show"

def test_all_methods_fail(monkeypatch):
    def fail_version(name):
        raise importlib.metadata.PackageNotFoundError

    class FakeProcess:
        def __init__(self):
            self.returncode = 1
            self.stdout = b""
            self.stderr = b""

    monkeypatch.setattr("importlib.metadata.version", fail_version)
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: FakeProcess())

    result = resolve_installed_package_info("nonexistent")
    assert result['available'] is False
    assert result['version'] is None
    assert result['source'] == "none"

def test_version_match(monkeypatch):
    monkeypatch.setattr("importlib.metadata.version", lambda _: "2.0.0")
    result = check_package_availability("flask", expected_version="2.0.0")
    assert result['available'] is True
    assert result['version_matches'] is True

def test_version_mismatch(monkeypatch):
    monkeypatch.setattr("importlib.metadata.version", lambda _: "2.1.0")
    result = check_package_availability("flask", expected_version="2.0.0")
    assert result['available'] is True
    assert result['version_matches'] is False

def test_validate_passes_with_defaults(monkeypatch):
    monkeypatch.setattr("pydepguard.pylock.validator.check_package_availability", lambda dep, ver=None: {
        'available': True,
        'version_matches': True,
        'version': ver,
        'source': 'importlib'
    })

    lockfile = {'deps': {'flask': {'version': '2.0.0'}}}
    validate_environment(lockfile)


def test_validate_missing_package_warn(monkeypatch):
    monkeypatch.setattr("pydepguard.pylock.validator.check_package_availability", lambda dep, ver=None: {
        'available': False,
        'version_matches': False,
        'version': None,
        'source': 'none'
    })

    lockfile = {'deps': {'flask': {'version': '2.0.0'}}}
    validate_environment(lockfile, on_error='warn', interactive=False)


def test_validate_version_mismatch_strict(monkeypatch):
    monkeypatch.setattr("pydepguard.pylock.validator.check_package_availability", lambda dep, ver=None: {
        'available': True,
        'version_matches': False,
        'version': '1.0.0',
        'source': 'importlib'
    })

    lockfile = {'deps': {'flask': {'version': '2.0.0'}}}
    with pytest.raises(RuntimeError, match="Validation failed due to version mismatch"):
        validate_environment(lockfile, interactive=False)


def test_validate_version_mismatch_non_strict(monkeypatch):
    monkeypatch.setattr("pydepguard.pylock.validator.check_package_availability", lambda dep, ver=None: {
        'available': True,
        'version_matches': False,
        'version': '1.0.0',
        'source': 'importlib'
    })

    lockfile = {'deps': {'flask': {'version': '2.0.0'}}}
    validate_environment(lockfile, strict=False, interactive=False)


def test_validate_malformed_lockfile():
    with pytest.raises(ValueError, match="Invalid lockfile format"):
        validate_environment({})


def test_validate_check_package_crashes_abort(monkeypatch):
    def raise_error(*args, **kwargs):
        raise Exception("Simulated failure")
    monkeypatch.setattr("pydepguard.pylock.validator.check_package_availability", raise_error)
    lockfile = {'deps': {'broken': {'version': '1.0.0'}}}
    with pytest.raises(RuntimeError, match="Dependency check failed for broken"):
        validate_environment(lockfile, on_error='abort')


def test_validate_check_package_crashes_warn(monkeypatch):
    def raise_error(*args, **kwargs):
        raise Exception("Simulated failure")
    monkeypatch.setattr("pydepguard.pylock.validator.check_package_availability", raise_error)
    lockfile = {'deps': {'broken': {'version': '1.0.0'}}}
    validate_environment(lockfile, on_error='warn')  # Should not raise


def test_validate_missing_package_skip(monkeypatch):
    monkeypatch.setattr("pydepguard.pylock.validator.check_package_availability", lambda dep, ver=None: {
        'available': False,
        'version_matches': False,
        'version': None,
        'source': 'none'
    })
    lockfile = {'deps': {'flask': {'version': '2.0.0'}}}
    validate_environment(lockfile, on_error='skip')  # Should not raise


def test_validate_version_mismatch_input_decline(monkeypatch):
    monkeypatch.setattr("pydepguard.pylock.validator.check_package_availability", lambda dep, ver=None: {
        'available': True,
        'version_matches': False,
        'version': '1.0.0',
        'source': 'importlib'
    })
    monkeypatch.setattr("builtins.input", lambda _: "no")
    lockfile = {'deps': {'flask': {'version': '2.0.0'}}}
    with pytest.raises(RuntimeError, match="Validation aborted due to version mismatch."):
        validate_environment(lockfile, strict=True, interactive=True)


def test_validate_version_mismatch_keyboard_interrupt(monkeypatch):
    monkeypatch.setattr("pydepguard.pylock.validator.check_package_availability", lambda dep, ver=None: {
        'available': True,
        'version_matches': False,
        'version': '1.0.0',
        'source': 'importlib'
    })
    monkeypatch.setattr("builtins.input", lambda _: (_ for _ in ()).throw(KeyboardInterrupt))
    lockfile = {'deps': {'flask': {'version': '2.0.0'}}}
    with pytest.raises(SystemExit) as e:
        validate_environment(lockfile, strict=True, interactive=True)
    assert e.value.code == 130

def test_validate_check_package_crashes_skip(monkeypatch):
    def raise_error(*args, **kwargs):
        raise Exception("Simulated failure")
    monkeypatch.setattr("pydepguard.pylock.validator.check_package_availability", raise_error)

    lockfile = {'deps': {'broken': {'version': '1.0.0'}}}
    # Should reach the final else branch under crash condition
    validate_environment(lockfile, on_error='skip')


def test_validate_missing_package_abort(monkeypatch):
    monkeypatch.setattr("pydepguard.pylock.validator.check_package_availability", lambda dep, ver=None: {
        'available': False,
        'version_matches': True,
        'version': None,
        'source': 'mock'
    })
    lockfile = {'deps': {'missing': {'version': '1.0.0'}}}
    with pytest.raises(RuntimeError, match="Missing required package: missing"):
        validate_environment(lockfile, on_error='abort')


def test_validate_missing_package_else_skip(monkeypatch):
    monkeypatch.setattr("pydepguard.pylock.validator.check_package_availability", lambda dep, ver=None: {
        'available': False,
        'version_matches': True,
        'version': None,
        'source': 'mock'
    })
    lockfile = {'deps': {'missing': {'version': '1.0.0'}}}
    validate_environment(lockfile, on_error='skip')


def test_validate_version_mismatch_warn(monkeypatch):
    monkeypatch.setattr("pydepguard.pylock.validator.check_package_availability", lambda dep, ver=None: {
        'available': True,
        'version_matches': False,
        'version': '0.9.0',
        'source': 'mock'
    })
    lockfile = {'deps': {'mismatch': {'version': '1.0.0'}}}
    validate_environment(lockfile, strict=True, interactive=False, on_error='warn')


def test_validate_version_mismatch_else_skip(monkeypatch):
    monkeypatch.setattr("pydepguard.pylock.validator.check_package_availability", lambda dep, ver=None: {
        'available': True,
        'version_matches': False,
        'version': '0.9.0',
        'source': 'mock'
    })
    lockfile = {'deps': {'mismatch': {'version': '1.0.0'}}}
    validate_environment(lockfile, strict=True, interactive=False, on_error='skip')

