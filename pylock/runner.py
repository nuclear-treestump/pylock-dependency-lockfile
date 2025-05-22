import subprocess
import sys

def execute_script(script_path):
    print(f"Running {script_path}...")
    process = subprocess.Popen([sys.executable, script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    if stdout:
        print(stdout.decode(), end='')
    if stderr:
        print(stderr.decode(), end='', file=sys.stderr)

    rc = process.returncode
    if rc != 0:
        print(f"Script exited with return code {rc}")