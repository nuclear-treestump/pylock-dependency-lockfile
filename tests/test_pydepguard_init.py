import pytest
import hashlib
import os
from pathlib import Path
import importlib.util
import pydepguardnext



def test_init_validate_self(capsys):
    def get_module_root():
        spec = importlib.util.find_spec("pydepguardnext")
        if spec is None or not spec.origin:
            return None
        path = Path(spec.origin).resolve()
        if path.name == "__init__.py":
            return path.parent
        return path

    def sha256sum_dir(directory: Path):
        h = hashlib.sha256()
        for file in sorted(directory.rglob("*.py")):
            with open(file, "rb") as f:
                while True:
                    block = f.read(8192)
                    if not block:
                        break
                    h.update(block)
        return h.hexdigest()
    os.environ["PYDEP_TRUSTED_HASH"] = sha256sum_dir(get_module_root())
    pydepguardnext.validate_self()
    captured = capsys.readouterr()
    assert "[pydepguard] ⚠ Using override hash:" in captured.out



def test_init_validate_self_hardened(capsys):
    def get_module_root():
        spec = importlib.util.find_spec("pydepguardnext")
        if spec is None or not spec.origin:
            return None
        path = Path(spec.origin).resolve()
        if path.name == "__init__.py":
            return path.parent
        return path

    def sha256sum_dir(directory: Path):
        h = hashlib.sha256()
        for file in sorted(directory.rglob("*.py")):
            with open(file, "rb") as f:
                while True:
                    block = f.read(8192)
                    if not block:
                        break
                    h.update(block)
        return h.hexdigest()
    os.environ["PYDEP_TRUSTED_HASH"] = sha256sum_dir(get_module_root())
    os.environ["PYDEP_HARDENED"] = "1"
    with pytest.raises(pydepguardnext.PyDepBullshitDetectionError):
        pydepguardnext.validate_self()
