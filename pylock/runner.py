import subprocess

def execute_script(script_path):
    print(f"Running {script_path}...")
    process = subprocess.Popen(['python', script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    while True:
        output = process.stdout.readline()
        if output == b'' and process.poll() is not None:
            break
        if output:
            print(output.strip().decode())
    rc = process.poll()
    if rc != 0:
        print(f"Script exited with return code {rc}")