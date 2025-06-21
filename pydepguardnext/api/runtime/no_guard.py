import subprocess
import sys
from pydepguardnext.api.log.logit import logit

def run_without_guard(script_path):
    logit(f"Running {script_path}...", "i")
    process = subprocess.Popen([sys.executable, script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    if stdout:
        logit(stdout.decode(), "i")
        print(stdout.decode(), end='')
    if stderr:
        logit(stderr.decode(), "e")
        print(stderr.decode(), end='', file=sys.stderr)

    rc = process.returncode
    if rc != 0:
        logit(f"Script exited with return code {rc}", "e")