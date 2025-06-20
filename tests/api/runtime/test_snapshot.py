import pydepguardnext.api.runtime.snapshot as snapshot
import tempfile
import os
from pathlib import Path


def test_snapshot_script_creates_backup():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tmp:
        tmp.write("print('test')\n")
        path = Path(tmp.name)

    backup_path = snapshot.snapshot_script(str(path))
    assert Path(backup_path).exists()
    os.remove(backup_path)
    os.remove(path)

