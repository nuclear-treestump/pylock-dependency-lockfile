import sys
import builtins
import types
import pytest
from unittest.mock import patch
import pydepguardnext.api.runtime.importer as importer


def test_import_hook_installs_missing_package(monkeypatch):
    call_log = []

    # Simulate a finder that fails the first time but succeeds on retry
    def conditional_find_spec(name, *args, **kwargs):
        if name == "missinglib" and not call_log:
            call_log.append("failed")
            raise ModuleNotFoundError
        return types.SimpleNamespace(name=name)

    def fake_install(cmd, *args, **kwargs):
        call_log.append(f"pip {cmd}")

    monkeypatch.setattr("importlib.util.find_spec", conditional_find_spec)
    monkeypatch.setattr("subprocess.check_call", fake_install)

    finder = importer.AutoInstallFinder()
    spec = finder.find_spec("missinglib", None)

    assert spec is not None
    assert any("pip" in c for c in call_log)

def test_safe_import_patch(monkeypatch):
    call_log = []

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "somepkg":
            call_log.append(name)
            raise ImportError("fail")
        return _real_import(name, globals, locals, fromlist, level)

    _real_import = builtins.__import__

    with patch("builtins.__import__", new=fake_import):
        with pytest.raises(ImportError):
            __import__("somepkg") 

    assert "somepkg" in call_log
