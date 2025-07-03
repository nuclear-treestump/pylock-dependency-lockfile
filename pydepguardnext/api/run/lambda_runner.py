# Lambda Runner for PyDepGuardNext
# This module handles running Python scripts in a Lambda-like environment.
from pydepguardnext.api.log.logit import logit
from pathlib import Path
import sys

logslug = "api.run.lambda_runner"

def run_lambda_script(script: Path, ctx, args):
    logit("Running in Lambda mode", "i", source=f"{logslug}.{run_lambda_script.__name__}")
    logit(f"Policy context: {ctx}", "i", source=f"{logslug}.{run_lambda_script.__name__}")
    repair_mode = False

    if args.lambda_name:
        lambda_name = args.lambda_name
    if args.lambda_path:
        lambda_path = Path(args.lambda_path).resolve()
        if not lambda_path.exists() or not lambda_path.is_dir():
            logit(f"Invalid Lambda path: {lambda_path}", "e", source=f"{logslug}.{run_lambda_script.__name__}")
            sys.exit(1)
    else:
        from hashlib import sha256
        with open(script, "rb") as f:
            script_bytes = f.read()
        lambda_name = sha256(script_bytes).hexdigest()
        lambda_path = Path(".") / ".pydepguardenv" / "lambda" / lambda_name
        lambda_path.mkdir(parents=True, exist_ok=True)
        logit(f"Using default Lambda path: {lambda_path}", "i", source=f"{logslug}.{run_lambda_script.__name__}")
    if args.prewarm:
        logit("Analyzing script for prewarming", "i", source=f"{logslug}.{run_lambda_script.__name__}")
        from pydepguardnext.api.deps.walker import scan_script_by_mode
        results = scan_script_by_mode(script, mode="top")
        if results:
            logit(f"Prewarming Lambda environment with {len(results)} top-level imports", "i", source=f"{logslug}.{run_lambda_script.__name__}")
        else:
            logit("No top-level imports found for prewarming", "w", source=f"{logslug}.{run_lambda_script.__name__}")
    if args.repair:
        repair_mode = True
        logit("Repair mode enabled", "i", source=f"{logslug}.{run_lambda_script.__name__}")
    from pydepguardnext.api.runtime.pydep_lambda import create_lambda_venv, launch_lambda_runtime
    from pydepguardnext.api.runtime.airjail import prepare_fakeroot
    with open(script, "r", encoding="utf-8") as f:
        script_content = f.read()
    script.write_text(script_content)
    app_dir, bindir, python_bin, path_var, venv_var = prepare_fakeroot(script_path=script, hash_suffix=lambda_name, base_dir=lambda_path, persist=args.persist)
    py_bin = create_lambda_venv(app_dir, Path("."))
    results = launch_lambda_runtime(py_bin, app_dir, stdin_ok=args.stdin_ok, teardown=args.teardown, jit_deps=repair_mode, path_var=path_var, venv_var=venv_var)
    
