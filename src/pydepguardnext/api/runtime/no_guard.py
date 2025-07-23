logslug = "api.runtime.no_guard"

def run_without_guard(script_path):
    from pydepguardnext.api.log.logit import logit
    from subprocess import Popen, PIPE
    from time import time
    from sys import executable
    logit(f"Running {script_path}...", "i", source=f"{logslug}.{run_without_guard.__name__}")
    time_start = time()
    process = Popen([executable, script_path], stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()

    if stdout:
        logit(stdout.decode(), "i", source=f"{logslug}.{run_without_guard.__name__}")
    if stderr:
        logit(stderr.decode(), "e", source=f"{logslug}.{run_without_guard.__name__}")

    rc = process.returncode
    time_end = time() - time_start
    logit(f"PyDepGuard script run executed in {time_end:.2f} seconds", "i", source=f"{logslug}.{run_without_guard.__name__}")
    if rc != 0:
        logit(f"Script exited with return code {rc}", "e", source=f"{logslug}.{run_without_guard.__name__}")