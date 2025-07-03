import pydepguardnext.api.runtime.guard as guard
import pydepguardnext.api.runtime.importer as importer
from pydepguardnext.api.errors import RuntimeInterdictionError
import tempfile
import builtins
import subprocess
import runpy
from pathlib import Path
import pytest
import importlib.util
import sys
import os
from textwrap import dedent


def is_installed(pkg_name: str) -> bool:
    return importlib.util.find_spec(pkg_name) is not None

def uninstall_if_installed(pkg_name: str):
    print(f"Uninstalling {pkg_name} if it exists...")
    if is_installed(pkg_name):
        subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "-y", pkg_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) 

def reinstall_if_needed(pkg_name: str, was_installed: bool):
    print(f"Reinstalling {pkg_name} if it was previously installed...")
    if was_installed:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def test_run_with_repair_success(monkeypatch):
    monkeypatch.setattr(guard, "install_missing_and_retry", lambda path: ("success", None))
    result = guard.run_with_repair("fake.py")
    assert result == "success"



def test_run_with_repair_importerror(monkeypatch):
    attempts = []

    def fail_once(path):
        if len(attempts) < 1:
            attempts.append("fail")
            raise ImportError("fake")
        return "recovered"

    monkeypatch.setattr(guard, "install_missing_and_retry", fail_once)
    result = guard.run_with_repair("retryme.py", max_retries=2)
    assert result == "recovered"



def test_run_with_repair_non_import_failure(monkeypatch):
    def crash(path):
        raise RuntimeError("boom")

    monkeypatch.setattr(importer, "install_missing_and_retry", crash)
    result = guard.run_with_repair("boom.py", max_retries=1)
    assert result is None

def test_run_with_repair_retries_until_success(monkeypatch):
    attempts = []

    def fail_twice_then_succeed(path):
        if len(attempts) < 2:
            attempts.append("fail")
            raise ImportError("Missing soft dep")
        return "recovered"

    monkeypatch.setattr(guard, "install_missing_and_retry", fail_twice_then_succeed)

    result = guard.run_with_repair("script.py", max_retries=5)
    assert result == "recovered"
    assert len(attempts) == 2

### Try as I might, I cannot get any working test for the integrity check.
### Because all of the guarded functions are import related, they blow up
### before the integrity check can even run.
### And I'd rather not build a dummy function just to test the integrity check.
### It definitely works, but I cannot get it to run in a test.
### If anyone has a suggestion on how to test this, please let me know.
### I feel like I'm pentesting myself here. This is a bit ridiculous.

# INTEGRATION TESTS

@pytest.mark.integration
# Note, this test requires the 'requests' package to be installed initially.
# It will uninstall it, run a script that requires 'requests', and then reinstall it.
# Sorry for the inconvenience, but this is necessary to test the repair loop.
def test_full_repair_loop_with_real_requests():
    was_installed = is_installed("requests")
    uninstall_if_installed("requests")

    code = "import requests\nprint('Recovered')\n"
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tmp:
        tmp.write(code)
        script_path = Path(tmp.name)

    try:
        result = guard.run_with_repair(str(script_path), max_retries=3)

        assert result and result["__name__"] == "<run_path>"
        assert "__file__" in result
    finally:
        reinstall_if_needed("requests", was_installed)
        script_path.unlink()

@pytest.mark.integration
# This test is using the known script "new_script.py" which is in 
# the repo. If you really want to test this, make sure that the script exists
# and is a valid Python script that imports 'requests'.
def test_full_repair_loop_with_known_script():
    was_installed = is_installed("openpyxl")
    uninstall_if_installed("openpyxl")

    script_path = Path("new_script.py")
    print(script_path)

    try:
        result = guard.run_with_repair(str(script_path), max_retries=3) 
        assert result and result["__name__"] == "<run_path>"
        assert "__file__" in result
    finally:
        reinstall_if_needed("requests", was_installed)


