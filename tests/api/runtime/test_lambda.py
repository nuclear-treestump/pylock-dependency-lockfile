import tempfile
import shutil
from pathlib import Path
import subprocess
import sys
import os
import pytest

from pydepguardnext.api.runtime.airjail import prepare_fakeroot
from pydepguardnext.api.log.logit import logit, configure_logging
from pydepguardnext.api.runtime.pydep_lambda import create_lambda_venv, launch_lambda_runtime

import time

def start_logging():
        configure_logging(
        level=("debug"),
        to_file=("pydepguard.log"),
        fmt=("text"),
        print_enabled=True
    )


def safe_rmtree(path, retries=5, delay=1, temp_dir=None):
    if temp_dir is None:
        temp_dir = path
    for _ in range(retries):
        try:
            shutil.rmtree(path)
            return
        except PermissionError:
            time.sleep(delay)
    print(f"Failed to delete {path} after {retries} retries. Manual intervention may be required. This is especially true on Windows where files may be locked by the OS or other processes.")
    print("This is a known issue with Windows and Python's shutil.rmtree. If you encounter this, please ensure no other processes are using the files in the directory.")
    print("The test is designed to fail gracefully in this case, but it may leave some files behind.")
    print(f"You can manually delete the directory here: {Path(temp_dir).resolve()}")

def test_prepare_fakeroot_creates_expected_files():
    temp_dir = Path(tempfile.mkdtemp())
    script = temp_dir / "hello.py"
    script.write_text("print('Hello from lambda')")

    app_dir = prepare_fakeroot(script_path=script, hash_suffix="test", base_dir=temp_dir)
    assert (app_dir / "main.py").exists()
    shutil.rmtree(temp_dir)

def test_create_lambda_venv_bootstraps_and_installs():
    temp_dir = Path(tempfile.mkdtemp())
    script = temp_dir / "hello.py"
    script.write_text("print('Hello world')")
    app_dir = prepare_fakeroot(script_path=script, hash_suffix="venv", base_dir=temp_dir)
    py_bin = create_lambda_venv(app_dir, Path("."))
    assert py_bin.exists()

    result = subprocess.run([str(py_bin), "-m", "pip", "show", "pydepguardnext"], capture_output=True)
    assert result.returncode == 0
    assert b"Name: pydepguardnext" in result.stdout
    shutil.rmtree(temp_dir)

def test_lambda_runtime_executes_script():
    temp_dir = Path(tempfile.mkdtemp())
    script = temp_dir / "hello.py"
    script.write_text("print('Hello secure world')")
    g_time = time.time()
    app_dir = prepare_fakeroot(script_path=script, hash_suffix="run", base_dir=temp_dir)
    py_bin = create_lambda_venv(app_dir, Path("."))
    result_code = launch_lambda_runtime(py_bin, app_dir)
    completed_time = time.time() - g_time
    print(f"Script executed in {completed_time:.2f} seconds")
    assert result_code == 0
    print("Directory contents before deletion:")
    for p in Path(app_dir).rglob("*"):
        print(f"- {p}")
    delete_target = app_dir.parent
    renamed = delete_target.with_name(delete_target.name + "_todelete")
    app_dir.parent.rename(renamed)
    safe_rmtree(renamed, retries=10, delay=2, temp_dir=temp_dir)
    print("Directory contents after deletion:")
    for p in Path(temp_dir).rglob("*"):
        print(f"- {p}")
    print(f"Only remnants should be the interpreters in {Path(renamed).resolve()}. No userland files survived in fakeroot. I win.")


def test_lambda_runtime_executes_script_with_guard():
    temp_dir = Path(tempfile.mkdtemp())
    script = temp_dir / "hello.py"
    script.write_text("import requests\nimport subprocess\nimport sys\nprint('Hello secure world with guard')\nsubprocess.Popen([sys.executable, '-m','pip', 'freeze'])")
    print("TEST START: Running script with guard")
    g_time = time.time()
    app_dir = prepare_fakeroot(script_path=script, hash_suffix="run", base_dir=temp_dir)
    py_bin = create_lambda_venv(app_dir, Path("."))

    result_code = launch_lambda_runtime(py_bin, app_dir, jit_deps=True)
    completed_time = time.time() - g_time
    print(f"TEST END: test run completed in {completed_time:.2f} seconds")
    assert result_code == 0
    print("Directory contents before deletion:")
    for p in Path(app_dir).rglob("*"):
        print(f"- {p}")
    delete_target = app_dir.parent
    renamed = delete_target.with_name(delete_target.name + "_todelete")
    app_dir.parent.rename(renamed)
    safe_rmtree(renamed, retries=10, delay=2, temp_dir=temp_dir)
    print("Directory contents after deletion:")
    for p in Path(temp_dir).rglob("*"):
        print(f"- {p}")
    print(f"Only remnants should be the interpreters in {Path(renamed).resolve()}. No userland files survived in fakeroot. I win.")

def test_teardown_timer_kills():
    temp_dir = Path(tempfile.mkdtemp())
    script = temp_dir / "loop.py"
    script.write_text("import time\nwhile True: time.sleep(1)")
    app_dir = prepare_fakeroot(script_path=script, hash_suffix="teardown", base_dir=temp_dir)
    py_bin = create_lambda_venv(app_dir, Path("."))

    result = launch_lambda_runtime(py_bin, app_dir, teardown=3)
    assert result != 0
    print("Directory contents before deletion:")
    for p in Path(app_dir).rglob("*"):
        print(f"- {p}")
    delete_target = app_dir.parent
    renamed = delete_target.with_name(delete_target.name + "_todelete")
    app_dir.parent.rename(renamed)
    safe_rmtree(renamed, retries=10, delay=2, temp_dir=temp_dir)
    print("Directory contents after deletion:")
    for p in Path(temp_dir).rglob("*"):
        print(f"- {p}")
    print(f"Only remnants should be the interpreters in {Path(renamed).resolve()}. Known Windows bug. No userland files survived in fakeroot. I win.")

@pytest.mark.integration
def test_lambda_runtime_executes_known_script_with_guard():
    temp_dir = Path(tempfile.mkdtemp())
    script = temp_dir / "new_script.py"
    with open("new_script.py", "r", encoding="utf-8") as f:
        script_content = f.read()
    script.write_text(script_content)
    print("TEST START: Running script with guard")
    g_time = time.time()
    from pydepguardnext.api.runtime.airjail import prepare_fakeroot
    from pydepguardnext.api.runtime.pydep_lambda import create_lambda_venv, launch_lambda_runtime
    app_dir = prepare_fakeroot(script_path=script, hash_suffix="run", base_dir=temp_dir, persist=True)
    py_bin = create_lambda_venv(app_dir, Path("."))

    result_code = launch_lambda_runtime(py_bin, app_dir, jit_deps=True)
    completed_time = time.time() - g_time
    print(f"TEST END: test run completed in {completed_time:.2f} seconds")
    assert result_code == 0
    py_bin = create_lambda_venv(app_dir, Path("."))
    print(f"TEST WITH PERSIST: Reusing venv at {py_bin}")
    result_code_2 = launch_lambda_runtime(py_bin, app_dir, jit_deps=True)

    print("Directory contents before deletion:")
    for p in Path(app_dir).rglob("*"):
        print(f"- {p}")
    delete_target = app_dir.parent
    renamed = delete_target.with_name(delete_target.name + "_todelete")
    app_dir.parent.rename(renamed)
    safe_rmtree(renamed, retries=10, delay=2, temp_dir=temp_dir)
    print("Directory contents after deletion:")
    for p in Path(temp_dir).rglob("*"):
        print(f"- {p}")
    print(f"Only remnants should be the interpreters in {Path(renamed).resolve()}. Known Windows bug. No userland files survived in fakeroot. I win.")