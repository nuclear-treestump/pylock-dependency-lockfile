from pathlib import Path
from subprocess import run, check_call
from pathlib import Path
from shutil import copytree, ignore_patterns
from importlib.util import find_spec
import sys
import os
from pydepguardnext.api.log.logit import logit

logslug = "api.runtime.pydep_lambda"

def copy_pydepguard_to_venv(python_bin: Path, venv_dir: Path):
    # Detect where pydepguardnext is installed in the parent interpreter
    parent_site_pkg = next(p for p in sys.path if "site-packages" in p and Path(p).exists())
    venv_site_pkg = next(p for p in run(
        [str(python_bin), "-c", "import site; print('\\n'.join(site.getsitepackages()))"],
        capture_output=True,
        text=True
    ).stdout.splitlines() if "site-packages" in p and Path(p).exists())

    pdg_dir = find_spec("pydepguardnext").origin
    pdg_pkg_dir = str(Path(pdg_dir).parent)  # e.g., .../site-packages/pydepguardnext

    dest = Path(venv_site_pkg) / "pydepguardnext"

    if Path(pdg_pkg_dir).name != "pydepguardnext":
        raise RuntimeError("pydepguardnext package location could not be resolved correctly.")

    if dest.exists():
        logit(f"pydepguardnext already exists in venv: {dest}", "i", source=f"{logslug}.{copy_pydepguard_to_venv.__name__}")
        return

    logit(f"Copying pydepguardnext from {pdg_pkg_dir} to {dest}", "i", source=f"{logslug}.{copy_pydepguard_to_venv.__name__}")
    copytree(pdg_pkg_dir, dest, ignore=ignore_patterns("__pycache__"))

def create_lambda_venv(app_dir: Path, project_root: Path) -> Path:
    from venv import EnvBuilder
    from subprocess import check_call, run
    from pydepguardnext.api.log.logit import logit
    from time import time
    from os import name as os_name
    venv_dir = app_dir.parent / "venv"
    logit(f"Creating venv at {venv_dir}", "i", source=f"{logslug}.{create_lambda_venv.__name__}")
    builder = EnvBuilder(with_pip=True)
    builder.create(venv_dir)

    python_bin = venv_dir / "Scripts" / "python.exe" if os_name == "nt" else venv_dir / "bin" / "python"
    check_result = run(
    [str(python_bin), "-m", "pip", "show", "pydepguardnext"],
    capture_output=True)
    time_install = time()
    logit("Installing pydepguard into venv", "i", source=f"{logslug}.{create_lambda_venv.__name__}")
    if check_result.returncode == 0:
        logit("pydepguardnext is already installed in the venv, skipping installation", "i", source=f"{logslug}.{create_lambda_venv.__name__}")
        return python_bin
    try:
        copy_pydepguard_to_venv(python_bin, venv_dir)
    except Exception as e:
        logit(f"Failed to copy pydepguardnext: {e}. Falling back to pip install.", "w", source=logslug)
        check_call([str(python_bin), "-m", "pip", "install", "."], cwd=str(project_root))
    time_install_done = time() - time_install
    logit(f"Installed pydepguard in {time_install_done:.2f} seconds", "i", source=f"{logslug}.{create_lambda_venv.__name__}")
    return python_bin

def launch_lambda_runtime(python_bin: Path, app_dir: Path, stdin_ok: bool = False, teardown: int = 0, jit_deps: bool = False, path_var: str = None, venv_var: str = None) -> int:
    from pydepguardnext.api.log.logit import logit
    from pydepguardnext import GLOBAL_INTEGRITY_CHECK
    from subprocess import Popen
    from threading import Timer
    from time import time
    from sys import stdin
    from os import environ
    from json import dumps as json_dumps
    from pydepguardnext.api.secrets import os_patch, secretentry
    script_path = app_dir / "main.py"
    args = [str(python_bin), "-m", "pydepguardnext", "run", str(script_path)]
    secure_args = [str(python_bin), "-m", "pydepguardnext", "run", "--repair", str(script_path)] if jit_deps else args
    logit(f"Launching script at {script_path}", "i", source=f"{logslug}.{launch_lambda_runtime.__name__}")
    run_time = time()
    from pydepguardnext import _MANIFEST
    pydep_manifest = {"app_dir": str(app_dir), "script": str(script_path)} or _MANIFEST
    secmap = secretentry.PyDepSecMap()
    parent_uuid = f"{GLOBAL_INTEGRITY_CHECK.get('global_.jit_check_uuid')}"
    secmap.add("PYDEP_CHILD", secretentry.SecretEntry("1", mock_env=True, mock_env_name="PYDEP_CHILD"))
    secmap.add("PYDEP_MANIFEST", secretentry.SecretEntry(json_dumps(pydep_manifest), mock_env=True, mock_env_name="PYDEP_MANIFEST"))
    secmap.add("PYDEP_PARENT_UUID", secretentry.SecretEntry(parent_uuid, mock_env=True, mock_env_name="PYDEP_PARENT_UUID"))
    secmap.add("PYDEP_NO_CAPTURE", secretentry.SecretEntry("1", mock_env=True, mock_env_name="PYDEP_NO_CAPTURE"))
    secmap.add("PATH", secretentry.SecretEntry(str(path_var), mock_env=True, mock_env_name="PATH"))
    secmap.add("VIRTUAL_ENV", secretentry.SecretEntry(str(venv_var), mock_env=True, mock_env_name="VIRTUAL_ENV"))
    os.environ.pop("PYDEP_STANDALONE_NOSEC", None)

    for env in environ:
        if env.startswith("PYDEP_") or env.startswith("VSCODE"):
            secmap.add(env, secretentry.SecretEntry(environ[env], mock_env=True, mock_env_name=env))
    myenv = secmap.to_env()
    print("Environment Variables for Lambda Runtime:")
    for k, v in myenv.items():
        print(f"{k}={v}")
    print("Environment Variables from os.environ:")
    for k, v in environ.items():
        print(f"{k}={v}")
    print("Missing From myenv:")
    for k, v in environ.items():
        if k not in myenv:
            print(f"{k}={v}")
    if stdin_ok:
        logit("Forwarding stdin to lambda runtime", "i", source=f"{logslug}.{launch_lambda_runtime.__name__}")
        proc = Popen(secure_args if jit_deps else args, stdin=stdin, env=myenv)
    else:
        proc = Popen(secure_args if jit_deps else args)

    if teardown > 0:
        def kill_proc():
            logit(f"Lambda teardown triggered after {teardown}s", "i", source=f"{logslug}.{launch_lambda_runtime.__name__}")
            proc.kill()
            run_time_done = time() - run_time
            logit(f"PyDepGuard lambda reported execution time in {run_time_done:.2f} seconds", "i", source=f"{logslug}.{launch_lambda_runtime.__name__}")
            proc.wait(timeout=5)
        Timer(teardown, kill_proc).start()

    proc.wait()
    run_time_done = time() - run_time
    logit(f"PyDepGuard lambda reported execution time in {run_time_done:.2f} seconds", "i", source=f"{logslug}.{launch_lambda_runtime.__name__}")
    return proc.returncode


