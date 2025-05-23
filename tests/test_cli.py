import os
import json
import tempfile
from pathlib import Path
from pydepguard.pylock.cli import main as pylock_main
from pydepguard.pylock.lockfile import LockfileManager
import subprocess
import sys


def test_cli_generate_validate_run(monkeypatch, capsys):
    code = (
        "import requests\n"
        "import json\n"
        "from math import sqrt\n"
        "print('PyLock CLI Test Success')"
    )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as tmp:
        tmp.write(code)
        script_path = tmp.name

    lockfile_path = Path(script_path).parent / ".pylock" / f"{Path(script_path).stem}_dep.lck"

    try:
        sys.argv = ["pylock", script_path, "--generate"]
        pylock_main()
        assert lockfile_path.exists()

        sys.argv = ["pylock", script_path, "--validate"]
        monkeypatch.setattr("builtins.input", lambda _: "yes")
        pylock_main()

        sys.argv = ["pylock", script_path, "--run"]
        pylock_main()
        out = capsys.readouterr().out
        print(out)
        assert "PyLock CLI Test Success" in out

        data = json.loads(lockfile_path.read_text())
        print(json.dumps(data, indent=4))
        assert "requests" in data["deps"]
        assert "version" in data["deps"]["requests"]
        assert "tree" in data["deps"]["requests"]

    finally:
        if lockfile_path.exists():
            os.remove(lockfile_path)
        if Path(script_path).exists():
            os.remove(script_path)
        pylock_dir = Path(script_path).parent / ".pylock"
        if pylock_dir.exists() and not any(pylock_dir.iterdir()):
            pylock_dir.rmdir()

def test_cli_help_output(capsys):
    sys.argv = ["pylock", "dummy.py"]
    try:
        pylock_main()
    except SystemExit:
        pass

    captured = capsys.readouterr()
    assert "[pylock] Error: File not found: dummy.py" in captured.err

def test_cli_explicit_help(capsys):
    sys.argv = ["pylock", "--help"]
    try:
        pylock_main()
    except SystemExit:
        pass

    captured = capsys.readouterr()
    assert "PyLock: A gatekeeper dependency validator for Python scripts" in captured.out
    assert "Usage: pylock script.py" in captured.out
    assert "--generate" in captured.out
    assert "--validate" in captured.out
    assert "--run" in captured.out