import subprocess
import sys
import os
import threading
from pathlib import Path
import venv
from pydepguardnext.api.log.logit import logit
import time
from importlib import metadata

logslug = "api.runtime.pydep_lambda"

def create_lambda_venv(app_dir: Path, project_root: Path) -> Path:
    venv_dir = app_dir.parent / "venv"
    logit(f"Creating venv at {venv_dir}", "i", source=f"{logslug}.{create_lambda_venv.__name__}")

    builder = venv.EnvBuilder(with_pip=True)
    builder.create(venv_dir)

    python_bin = venv_dir / "Scripts" / "python.exe" if os.name == "nt" else venv_dir / "bin" / "python"
    check_result = subprocess.run(
    [str(python_bin), "-m", "pip", "show", "pydepguardnext"],
    capture_output=True)
    time_install = time.time()
    logit("Installing pydepguard into venv", "i", source=f"{logslug}.{create_lambda_venv.__name__}")
    if check_result.returncode == 0:
        logit("pydepguardnext is already installed in the venv, skipping installation", "i", source=f"{logslug}.{create_lambda_venv.__name__}")
        return python_bin
    subprocess.check_call([str(python_bin), "-m", "pip", "install", "."], cwd=str(project_root))
    time_install_done = time.time() - time_install
    logit(f"Installed pydepguard in {time_install_done:.2f} seconds", "i", source=f"{logslug}.{create_lambda_venv.__name__}")

    return python_bin

def launch_lambda_runtime(python_bin: Path, app_dir: Path, stdin_ok: bool = False, teardown: int = 0, jit_deps: bool = False) -> int:
    script_path = app_dir / "main.py"
    args = [str(python_bin), "-m", "pydepguardnext", "--run", str(script_path)]
    secure_args = [str(python_bin), "-m", "pydepguardnext", "--run", "--repair", str(script_path)] if jit_deps else args
    logit(f"Launching script at {script_path}", "i", source=f"{logslug}.{launch_lambda_runtime.__name__}")
    run_time = time.time()
    if stdin_ok:
        logit("Forwarding stdin to lambda runtime", "i", source=f"{logslug}.{launch_lambda_runtime.__name__}")
        proc = subprocess.Popen(secure_args if jit_deps else args, stdin=sys.stdin)
    else:
        proc = subprocess.Popen(secure_args if jit_deps else args)

    if teardown > 0:
        def kill_proc():
            logit(f"Lambda teardown triggered after {teardown}s", "i", source=f"{logslug}.{launch_lambda_runtime.__name__}")
            proc.kill()
            run_time_done = time.time() - run_time
            logit(f"PyDepGuard lambda reported execution time in {run_time_done:.2f} seconds", "i", source=f"{logslug}.{launch_lambda_runtime.__name__}")
            proc.wait(timeout=5)
        threading.Timer(teardown, kill_proc).start()

    proc.wait()
    run_time_done = time.time() - run_time
    logit(f"PyDepGuard lambda reported execution time in {run_time_done:.2f} seconds", "i", source=f"{logslug}.{launch_lambda_runtime.__name__}")
    return proc.returncode


