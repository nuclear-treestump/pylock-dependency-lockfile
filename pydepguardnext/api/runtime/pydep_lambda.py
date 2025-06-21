import subprocess
import sys
import os
import threading
from pathlib import Path
import venv
from pydepguardnext.api.log.logit import logit

def create_lambda_venv(app_dir: Path, project_root: Path) -> Path:
    venv_dir = app_dir.parent / "venv"
    logit(f"Creating venv at {venv_dir}", "i")

    builder = venv.EnvBuilder(with_pip=True)
    builder.create(venv_dir)

    python_bin = venv_dir / "Scripts" / "python.exe" if os.name == "nt" else venv_dir / "bin" / "python"

    logit("Installing pydepguard into venv", "i")
    subprocess.check_call([str(python_bin), "-m", "pip", "install", "."], cwd=str(project_root))

    return python_bin

def launch_lambda_runtime(python_bin: Path, app_dir: Path, stdin_ok: bool = False, teardown: int = 0, jit_deps: bool = False) -> int:
    script_path = app_dir / "main.py"
    args = [str(python_bin), "-m", "pydepguardnext", "--run", str(script_path)]
    secure_args = [str(python_bin), "-m", "pydepguardnext", "--run", "--repair", str(script_path)] if jit_deps else args
    logit(f"Launching script at {script_path}", "i")

    if stdin_ok:
        logit("Forwarding stdin to lambda runtime", "i")
        proc = subprocess.Popen(secure_args if jit_deps else args, stdin=sys.stdin)
    else:
        proc = subprocess.Popen(secure_args if jit_deps else args)

    if teardown > 0:
        def kill_proc():
            logit(f"Lambda teardown triggered after {teardown}s", "i")
            proc.kill()
            proc.wait(timeout=5) 
        threading.Timer(teardown, kill_proc).start()

    proc.wait()
    return proc.returncode


