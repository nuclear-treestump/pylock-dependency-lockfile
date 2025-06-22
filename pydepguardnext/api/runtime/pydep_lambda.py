import subprocess
import sys
import os
import threading
from pathlib import Path
import venv
from pydepguardnext.api.log.logit import logit
import time
from importlib import metadata

def create_lambda_venv(app_dir: Path, project_root: Path) -> Path:
    venv_dir = app_dir.parent / "venv"
    logit(f"Creating venv at {venv_dir}", "i")

    builder = venv.EnvBuilder(with_pip=True)
    builder.create(venv_dir)

    python_bin = venv_dir / "Scripts" / "python.exe" if os.name == "nt" else venv_dir / "bin" / "python"
    dists = metadata.distributions()
    time_install = time.time()
    logit("Installing pydepguard into venv", "i")
    if "pydepguardnext" in [dist.metadata["Name"].lower() for dist in dists]:
        logit("pydepguardnext is already installed in the venv, skipping installation", "i")
        return python_bin
    subprocess.check_call([str(python_bin), "-m", "pip", "install", "."], cwd=str(project_root))
    time_install_done = time.time() - time_install
    print(f"Installed pydepguard in {time_install_done:.2f} seconds")

    return python_bin

def launch_lambda_runtime(python_bin: Path, app_dir: Path, stdin_ok: bool = False, teardown: int = 0, jit_deps: bool = False) -> int:
    script_path = app_dir / "main.py"
    args = [str(python_bin), "-m", "pydepguardnext", "--run", str(script_path)]
    secure_args = [str(python_bin), "-m", "pydepguardnext", "--run", "--repair", str(script_path)] if jit_deps else args
    logit(f"Launching script at {script_path}", "i")
    run_time = time.time()
    if stdin_ok:
        logit("Forwarding stdin to lambda runtime", "i")
        proc = subprocess.Popen(secure_args if jit_deps else args, stdin=sys.stdin)
    else:
        proc = subprocess.Popen(secure_args if jit_deps else args)

    if teardown > 0:
        def kill_proc():
            logit(f"Lambda teardown triggered after {teardown}s", "i")
            proc.kill()
            run_time_done = time.time() - run_time
            print(f"PyDepGuard lambda reported execution time in {run_time_done:.2f} seconds")
            proc.wait(timeout=5)
        threading.Timer(teardown, kill_proc).start()

    proc.wait()
    run_time_done = time.time() - run_time
    print(f"PyDepGuard lambda reported execution time in {run_time_done:.2f} seconds")
    return proc.returncode


