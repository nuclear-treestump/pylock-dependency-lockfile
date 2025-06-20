import pytest
import types
import tempfile
import sys
from subprocess import run
from pathlib import Path
from pydepguardnext.api.jit import jit as jitmod
from pydepguardnext.api.errors import JITImportError
import importlib

@pytest.fixture(autouse=True)
def reset_guard():
    jitmod._jit_ast_check_cache = None

# --- 1. Literal string import works if already available ---
def test_jit_import_valid_literal(monkeypatch):
    monkeypatch.setattr(importlib, "import_module", lambda name: types.SimpleNamespace(__name__=name))
    assert jitmod.jit_import("json", "1.0.0") is True


# --- 2. Variable as module name raises JITImportError ---
def test_jit_import_rejects_variable_input_file():
    # Use install_missing=False so it doesn't reach pip
    code = """
from pydepguardnext.api.jit import jit_import
mod = "definitelynotarealmodule"
jit_import(mod, "1.0.0", install_missing=False)
"""

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tmp:
        tmp.write(code)
        tmp_path = Path(tmp.name)

    try:
        result = run([sys.executable, str(tmp_path)], capture_output=True, text=True)
        print("STDOUT:\n", result.stdout)
        print("STDERR:\n", result.stderr)
        assert "jit_import only accepts string literals" in result.stderr
        assert result.returncode != 0
    finally:
        tmp_path.unlink()

# --- 3. Bypass AST check with pydep_init=True ---
def test_jit_import_bypass_guard(monkeypatch):
    monkeypatch.setattr(importlib, "import_module", lambda name: types.SimpleNamespace(__name__=name))
    mod = "json"
    assert jitmod.jit_import(mod, "1.0.0", pydep_init=True)


# --- 4. Simulate install if module missing and install_missing=True ---
def test_jit_import_triggers_install(monkeypatch):
    jitmod._jit_ast_check_cache = None

    logs = []

    def fake_import(name):
        raise ImportError("simulated failure")

    def fake_check_call(cmd):
        logs.append(f"Called pip with: {cmd}")
        return 0  # simulate success

    monkeypatch.setattr(importlib, "import_module", fake_import)
    monkeypatch.setattr("subprocess.check_call", fake_check_call)

    assert jitmod.jit_import("somepkg", "1.2.3") is True
    assert any("somepkg==1.2.3" in log for log in logs)


# --- 5. Reject install if install_missing=False ---
def test_jit_import_missing_without_install(monkeypatch):
    monkeypatch.setattr(importlib, "import_module", lambda name: (_ for _ in ()).throw(ImportError("fail")))
    with pytest.raises(ImportError):
        jitmod.jit_import("ghostpkg", "0.0.0", install_missing=False)

def test_jit_guard_no_external_frame(monkeypatch):
    import pydepguardnext.api.jit.jit as jitmod
    jitmod._jit_ast_check_cache = None

    monkeypatch.setattr(jitmod.inspect, "stack", lambda: [
        type("FakeFrame", (), {"filename": "pydepguardnext/fake.py"})()
    ])

    jitmod._jit_guard("testmodule")

def test_jit_guard_ast_parse_fails(monkeypatch):
    import pydepguardnext.api.jit.jit as jitmod
    jitmod._jit_ast_check_cache = None

    monkeypatch.setattr(jitmod, "_get_user_script_filename", lambda: "nonexistent_file.py")

    jitmod._jit_guard("somepkg")

def test_jit_import_installs_without_version(monkeypatch):
    import pydepguardnext.api.jit.jit as jitmod
    jitmod._jit_ast_check_cache = True 

    logs = []

    monkeypatch.setattr(jitmod.importlib, "import_module", lambda name: (_ for _ in ()).throw(ImportError("fail")))
    monkeypatch.setattr(jitmod.subprocess, "check_call", lambda cmd: logs.append(cmd))

    result = jitmod.jit_import("pkgx", "*")
    assert result is True
    assert any("pkgx" in str(log) and "==" not in str(log) for log in logs)

def test_jit_guard_cache_false_raises():
    import pydepguardnext.api.jit.jit as jitmod
    jitmod._jit_ast_check_cache = False

    with pytest.raises(jitmod.errors.JITImportSecurityError):
        jitmod._jit_guard("something")