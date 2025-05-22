import os
import json
import tempfile
from pathlib import Path
from pylock.lockfile import LockfileManager

def test_lockfile_write_and_read():
    deps = {
        'requests': {
            'version': '2.31.0',
            'origin': 'script.py:10',
            'tree': ['urllib3', 'certifi']
        }
    }
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as tmp:
        script_path = tmp.name

    lm = LockfileManager(script_path)

    try:
        if os.path.exists(lm.lockfile_path):
            os.remove(lm.lockfile_path)

        lm.save(deps)
        assert os.path.exists(lm.lockfile_path)
        assert lm.exists() is True

        data = lm.load()
        assert 'meta' in data
        assert 'deps' in data
        assert data['deps'] == deps
        assert data['meta']['script'] == Path(script_path).stem
        assert 'last_modified' in data['meta']
        assert 'saved_on' in data['meta']

    finally:
        if os.path.exists(lm.lockfile_path):
            os.remove(lm.lockfile_path)
        if os.path.exists(script_path):
            os.remove(script_path)

def test_lockfile_exists_false():
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as tmp:
        script_path = tmp.name
    os.remove(script_path)

    lm = LockfileManager(script_path)
    if os.path.exists(lm.lockfile_path):
        os.remove(lm.lockfile_path)

    assert lm.exists() is False