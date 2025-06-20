import os
import tempfile
import subprocess
from pydepguard.pylock.runner import execute_script

def test_execute_script_runs_successfully(capsys):
    code = "print(\"Hello from test script\")"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as tmp:
        tmp.write(code)
        script_path = tmp.name

    try:
        execute_script(script_path)
        captured = capsys.readouterr()
        assert "Hello from test script" in captured.out
    finally:
        if os.path.exists(script_path):
            os.remove(script_path)

def test_execute_script_failure(capsys):
    code = "raise ValueError(\"Test error\")"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as tmp:
        tmp.write(code)
        script_path = tmp.name

    try:
        execute_script(script_path)
        captured = capsys.readouterr()
        assert "Test error" in captured.err
        assert "return code" in captured.out.lower()
    finally:
        if os.path.exists(script_path):
            os.remove(script_path)