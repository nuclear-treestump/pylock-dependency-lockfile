from pylock.lockfile import LockfileManager
import tempfile
import json
import os

def test_lockfile_write_and_read():
    deps = {'requests': {'version': '2.31.0'}}
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as tmp:
        script_path = tmp.name
        print(f"[TEST] Temp script path: {script_path}")

    lm = LockfileManager(script_path)
    lm.save(deps)

    print(f"[TEST] Lockfile saved as: {lm.lockfile_name}")
    assert os.path.exists(lm.lockfile_name)

    loaded = lm.load()
    print(f"[TEST] Loaded deps: {loaded['deps']}")
    assert 'requests' in loaded['deps']