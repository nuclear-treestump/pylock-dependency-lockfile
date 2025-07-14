import sys
import importlib
import os

def reset_module(name):
    """Force reload of the target module for a clean import"""
    if name in sys.modules:
        del sys.modules[name]
    importlib.invalidate_caches()


def test_standalone_flag_sets_env():
    reset_module("pydepguardnext.standalone.secrets_manager")

    # Clear env first
    os.environ.pop("PYDEP_STANDALONE_NOSEC", None)

    import pydepguardnext.standalone.secrets_manager  # noqa: F401

    assert os.environ.get("PYDEP_STANDALONE_NOSEC") == "1", "Expected PYDEP_STANDALONE_NOSEC to be set by import."


def test_standalone_import_skips_secure_boot(monkeypatch):
    # Clear modules and env to force full boot logic
    reset_module("pydepguardnext")
    os.environ.pop("PYDEP_STANDALONE_NOSEC", None)
    os.environ["PYDEP_NO_CAPTURE"] = "1"

    monkeypatch.setenv("PYDEP_STANDALONE_NOSEC", "1")
    from pydepguardnext.bootstrap.boot import run_boot
    run_boot(bootmode="standalone")
    import pydepguardnext.standalone.secrets_manager  # noqa: F401
    from pydepguardnext.bootstrap.modes import BootMode, RUNTIME_MODE
    print(RUNTIME_MODE)
    assert RUNTIME_MODE.mode != BootMode.SECURE, "Expected runtime mode to be set to STANDALONE."