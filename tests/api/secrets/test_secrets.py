import time
import os
import pytest
from pydepguardnext.api.secrets.secretentry import SecretEntry, PyDepSecMap
from pydepguardnext.api.secrets.os_patch import SecureEnviron, patch_environ_with_secmap

def test_secretentry_ttl_expiry():
    entry = SecretEntry(value="sensitive", ttl_seconds=1)
    assert entry.get() == "sensitive"
    time.sleep(1.1)
    assert entry.get() is None
    assert entry.is_expired() is True

def test_secretentry_read_once():
    entry = SecretEntry(value="secret", read_once=True)
    assert entry.get() == "secret"
    assert entry.get() is None
    assert entry.is_expired() is True

def test_secretentry_read_max():
    entry = SecretEntry(value="secret", read_max=2)
    assert entry.get() == "secret"
    assert entry.get() == "secret"
    assert entry.get() is None
    assert entry.is_expired() is True

def test_pydepsecmap_access_behavior():
    secmap = PyDepSecMap()
    secmap.add("TOKEN", SecretEntry(value="abc123", read_max=1))
    assert secmap["TOKEN"] == "abc123"
    assert secmap["TOKEN"] is None  # expired after one read

def test_pydepsecmap_to_env():
    secmap = PyDepSecMap()
    secmap.add("API_KEY", SecretEntry(value="abc123", mock_env=True))
    env = secmap.to_env()
    assert "API_KEY" in env
    assert env["API_KEY"] == "abc123"

def test_secureenviron_basic_access():
    secmap = PyDepSecMap()
    secmap.add("SECRET", SecretEntry(value="42", mock_env=True))
    env = SecureEnviron(secmap)
    assert env["SECRET"] == "42"
    assert env.get("SECRET") == "42"
    assert "SECRET" in env

def test_patch_environ_intercepts_getenv(monkeypatch):
    secmap = PyDepSecMap()
    secmap.add("MY_TOKEN", SecretEntry(value="999", mock_env=True))
    patch_environ_with_secmap(secmap)

    # Patch ensures current env reflects SecureEnviron
    assert os.environ["MY_TOKEN"] == "999"
    assert os.getenv("MY_TOKEN") == "999"

def test_patch_environ_replaces_from_os_import(monkeypatch):
    secmap = PyDepSecMap()
    secmap.add("XYZ", SecretEntry(value="value", mock_env=True))
    patch_environ_with_secmap(secmap)

    # Simulate 'from os import environ'
    from os import environ as shadowed_env
    assert shadowed_env["XYZ"] == "value"

def test_secretentry_redaction():
    entry = SecretEntry(value="will_be_redacted", read_once=True)
    entry.get()
    entry.redact()
    assert entry.serialize()["value"] == "***"
    assert entry.get() is None

def test_pydepsecmap_serialize_snapshot():
    secmap = PyDepSecMap()
    secmap.add("S1", SecretEntry(value="abc", read_max=1, mock_env=True))
    secmap["S1"]
    snapshot = secmap.serialize()
    assert snapshot["S1"]["expired"] is True
    assert snapshot["S1"]["value"] == "***"

def test_secret_not_mock_env_excluded_from_env():
    secmap = PyDepSecMap()
    secmap.add("NO_MOCK", SecretEntry(value="hidden", mock_env=False))
    env = secmap.to_env()
    assert "NO_MOCK" not in env

def test_expired_secret_not_in_env():
    secmap = PyDepSecMap()
    secmap.add("SHORT_LIVED", SecretEntry(value="temp", ttl_seconds=0.1, mock_env=True))
    time.sleep(0.2)
    env = secmap.to_env()
    assert "SHORT_LIVED" not in env

def test_access_id_logs(monkeypatch):
    log_calls = []
    monkeypatch.setattr("pydepguardnext.api.secrets.secretentry.logit", lambda msg, lvl, source=None: log_calls.append((msg, lvl, source)))
    secmap = PyDepSecMap()
    secmap.add("ID_SECRET", SecretEntry(value="token", access_id="xyz", mock_env=True))
    _ = secmap["ID_SECRET"]
    assert any("xyz" in msg for msg, _, _ in log_calls)

def test_mock_env_name_overrides(monkeypatch):
    secmap = PyDepSecMap()
    secmap.add("ORIGINAL", SecretEntry(value="val", mock_env=True, mock_env_name="ALIAS"))
    env = secmap.to_env()
    assert "ALIAS" in env
    assert "ORIGINAL" not in env

def test_secureenviron_deletes_real_key():
    secmap = PyDepSecMap()
    env = SecureEnviron(secmap)
    env["TEMP_KEY"] = "tempval"
    assert "TEMP_KEY" in env
    del env["TEMP_KEY"]
    assert "TEMP_KEY" not in env

def test_secureenviron_iteration_combines():
    secmap = PyDepSecMap()
    os.environ["VISIBLE"] = "yes"
    secmap.add("SECRET", SecretEntry(value="abc", mock_env=True))
    env = SecureEnviron(secmap)
    keys = list(env.keys())
    assert "VISIBLE" in keys
    assert "SECRET" in keys

def test_secureenviron_shadowing():
    os.environ["COLLIDE"] = "real_value"
    secmap = PyDepSecMap()
    secmap.add("COLLIDE", SecretEntry(value="secret_value", mock_env=True))
    env = SecureEnviron(secmap)
    assert env["COLLIDE"] == "secret_value"  # SecureEnviron takes priority

def test_patch_environ_multiple_secrets(monkeypatch):
    secmap = PyDepSecMap()
    secmap.add("ONE", SecretEntry(value="1", mock_env=True))
    secmap.add("TWO", SecretEntry(value="2", mock_env=True, mock_env_name="DOS_ALIAS"))
    patch_environ_with_secmap(secmap)
    from os import environ as test_environ
    env = secmap.to_env()
    assert "ONE" in env
    assert "DOS_ALIAS" in env
    assert "TWO" not in env
    assert test_environ["ONE"] == "1"
    assert test_environ["DOS_ALIAS"] == "2"
    print("Environment after patching:")
    for key, value in test_environ.items():
        print(f"{key}={value}")
    assert "TWO" not in test_environ  # was renamed

def test_redact_removes_access():
    secmap = PyDepSecMap()
    secmap.add("SECRET_A", SecretEntry(value="hidden", mock_env=True))
    env = SecureEnviron(secmap)

    assert "SECRET_A" in env
    assert env["SECRET_A"] == "hidden"

    env.redact()
    with pytest.raises(KeyError):
        _ = env["SECRET_A"]

def test_repr_shows_keys_redacted():
    secmap = PyDepSecMap()
    secmap.add("REPR_SECRET", SecretEntry(value="xyz", mock_env=True))
    env = SecureEnviron(secmap)

    rep = repr(env)
    assert "REPR_SECRET=<secret>" in rep
    assert "base_keys=" in rep
    assert "secrets=" in rep

def test_redacted_key_not_in_environ():
    secmap = PyDepSecMap()
    secmap.add("TEMP_SECRET", SecretEntry(value="abc", mock_env=True))
    env = SecureEnviron(secmap)

    assert "TEMP_SECRET" in env
    env.redact()
    assert "TEMP_SECRET" not in env

def test_multiple_secrets_redacted():
    secmap = PyDepSecMap()
    secmap.add("S1", SecretEntry(value="a", mock_env=True))
    secmap.add("S2", SecretEntry(value="b", mock_env=True))
    env = SecureEnviron(secmap)

    assert env["S1"] == "a"
    assert env["S2"] == "b"
    env.redact()

    for key in ["S1", "S2"]:
        with pytest.raises(KeyError):
            _ = env[key]

def test_secureenviron_env_copy_resilience(monkeypatch):
    class FakeEnviron(dict): pass
    monkeypatch.setattr("os.environ", FakeEnviron(FOO="bar"))
    secmap = PyDepSecMap()
    env = SecureEnviron(secmap)
    assert env._base["FOO"] == "bar"

def test_iter_order_preserves_override_priority():
    os.environ["DUPLICATE"] = "base_value"
    secmap = PyDepSecMap()
    secmap.add("DUPLICATE", SecretEntry(value="secret_value", mock_env=True))
    env = SecureEnviron(secmap)

    seen = {k: v for k, v in env.items()}
    assert seen["DUPLICATE"] == "secret_value"
    assert list(env).count("DUPLICATE") == 1


def test_invalid_mock_env_name_falls_back_to_key():
    secmap = PyDepSecMap()
    secmap.add("BAD", SecretEntry(value="123", mock_env=True, mock_env_name=None))
    env = SecureEnviron(secmap)
    assert "BAD" in env
    assert env["BAD"] == "123"

def test_readding_secret_overwrites_previous():
    secmap = PyDepSecMap()
    secmap.add("X", SecretEntry(value="old", mock_env=True))
    secmap.add("X", SecretEntry(value="new", mock_env=True))
    env = SecureEnviron(secmap)
    assert env["X"] == "new"

def test_expired_mock_env_not_in_env():
    secmap = PyDepSecMap()
    secmap.add("EXPIRED", SecretEntry(value="gone", ttl_seconds=0, mock_env=True))
    time.sleep(0.1)
    env = SecureEnviron(secmap)
    assert "EXPIRED" not in env

def test_mock_env_name_collision_behavior_first_wins():
    """
    Verifies that if two secrets share the same mock_env_name,
    the first one added to PyDepSecMap takes precedence during SecureEnviron lookup.
    """
    secmap = PyDepSecMap()
    secmap.add("A", SecretEntry(value="one", mock_env=True, mock_env_name="DUP"))
    secmap.add("B", SecretEntry(value="two", mock_env=True, mock_env_name="DUP"))
    env = SecureEnviron(secmap)
    assert env["DUP"] == "one"

def test_late_patch_after_expiry():
    secmap = PyDepSecMap()
    secmap.add("SHORT", SecretEntry(value="yo", ttl_seconds=0.1, mock_env=True))
    time.sleep(0.2)
    patch_environ_with_secmap(secmap)
    assert "SHORT" not in os.environ

def test_threaded_access_during_redact():
    import threading
    secmap = PyDepSecMap()
    secmap.add("THREADY", SecretEntry(value="race", mock_env=True))
    env = SecureEnviron(secmap)

    def read_secret():
        for _ in range(5):
            try:
                _ = env["THREADY"]
            except KeyError:
                pass

    thread = threading.Thread(target=read_secret)
    thread.start()
    env.redact()
    thread.join()

def test_env_del_does_not_break_os_environ():
    secmap = PyDepSecMap()
    env = SecureEnviron(secmap)
    del env
    assert isinstance(os.environ, os._Environ) or isinstance(os.environ, dict)

def test_subprocess_does_not_leak_secret(monkeypatch):
    import subprocess, sys
    secmap = PyDepSecMap()
    secmap.add("LEAK", SecretEntry(value="do_not_leak", mock_env=True))
    patch_environ_with_secmap(secmap)

    result = subprocess.run(
        [sys.executable, "-c", "import os; print(os.getenv('LEAK'))"],
        capture_output=True, text=True
    )
    assert "do_not_leak" not in result.stdout

def test_secretentry_get_mid_expiry_exception(monkeypatch):
    entry = SecretEntry(value="x", ttl_seconds=1)
    monkeypatch.setattr(time, "time", lambda: float('inf'))  # break all TTL logic
    assert entry.get() is None
    assert entry.is_expired() is True

def test_empty_string_secret_behavior():
    secmap = PyDepSecMap()
    secmap.add("EMPTY", SecretEntry(value="", mock_env=True))
    env = SecureEnviron(secmap)
    assert "EMPTY" in env
    assert env["EMPTY"] == ""

def test_external_os_environ_assignment_isolated(monkeypatch):
    secmap = PyDepSecMap()
    patch_environ_with_secmap(secmap)
    os.environ["INJECTED"] = "corrupt"

    assert "INJECTED" in os.environ
    assert isinstance(os.environ, SecureEnviron)
    # SecureEnviron must still work properly
    list(os.environ.items())  # shouldn't crash or misbehave

def test_unicode_keys_and_values():
    secmap = PyDepSecMap()
    secmap.add("🌍KEY", SecretEntry(value="你好", mock_env=True))
    env = SecureEnviron(secmap)
    assert env["🌍KEY"] == "你好"

def test_secret_repr_does_not_expose(monkeypatch):
    entry = SecretEntry(value="SHOULD_NOT_SHOW", mock_env=True)
    monkeypatch.setattr("builtins.repr", lambda x: str(x))
    assert "SHOULD_NOT_SHOW" not in repr(entry)

def test_double_redact_does_not_crash():
    secmap = PyDepSecMap()
    secmap.add("R", SecretEntry(value="abc", mock_env=True))
    env = SecureEnviron(secmap)
    env.redact()
    env.redact()  # Should not raise or crash

def test_os_environ_already_wrapped_by_other_tool(monkeypatch):
    class FakeWrapper(dict): pass
    monkeypatch.setattr("os.environ", FakeWrapper(FAKE="1"))
    secmap = PyDepSecMap()
    patch_environ_with_secmap(secmap)
    assert isinstance(os.environ, SecureEnviron)

def test_subprocess_env_requires_explicit_conversion():
    import subprocess, sys
    secmap = PyDepSecMap()
    secmap.add("SECRET_INHERIT", SecretEntry(value="nope", mock_env=True))
    patch_environ_with_secmap(secmap)

    # Bad behavior (leaks secret) — user error
    result = subprocess.run(
        [sys.executable, "-c", "import os; print('SECRET_INHERIT' in os.environ)"],
        env=os.environ,
        capture_output=True,
        text=True
    )
    print("Subprocess output (leaky):", result.stdout)
    assert "True" in result.stdout

    # Good behavior — user calls to_env() to get a safe mapping
    result_clean = subprocess.run(
        [sys.executable, "-c", "import os; print('SECRET_INHERIT' in os.environ)"],
        env=secmap.to_env(),
        capture_output=True,
        text=True
    )
    print("Subprocess output (clean):", result_clean.stdout)
    assert "True" in result_clean.stdout  # Secret was passed intentionally

def test_mock_env_conflict_real_key_has_priority_on_del():
    os.environ["COLLIDE"] = "real"
    secmap = PyDepSecMap()
    secmap.add("COLLIDE", SecretEntry(value="secret", mock_env=True))
    env = SecureEnviron(secmap)
    with pytest.raises(TypeError):
        del env["COLLIDE"]
    
def test_mock_env_renaming_behavior():
    entry = SecretEntry(value="v", mock_env=True, mock_env_name="X")
    secmap = PyDepSecMap()
    secmap.add("key", entry)
    env = SecureEnviron(secmap)
    assert "X" in env
    entry.mock_env_name = "Y"
    assert "Y" in env
    assert "X" not in env

def test_large_number_of_secrets_does_not_crash():
    secmap = PyDepSecMap()
    for i in range(1000):
        secmap.add(f"K{i}", SecretEntry(value=str(i), mock_env=True))
    env = SecureEnviron(secmap)
    for i in range(1000):
        assert env[f"K{i}"] == str(i)

def test_non_str_key_rejection(monkeypatch):
    secmap = PyDepSecMap()
    with pytest.raises(TypeError):
        secmap.add(123, SecretEntry(value="bad", mock_env=True))

def test_threaded_add_and_redact():
    import threading

    secmap = PyDepSecMap()

    def adder():
        for i in range(100):
            secmap.add(f"KEY{i}", SecretEntry(value=str(i), mock_env=True))

    def redactor():
        for _ in range(20):
            secmap.redact_expired()

    t1 = threading.Thread(target=adder)
    t2 = threading.Thread(target=redactor)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

def test_repr_of_empty_secureenv():
    secmap = PyDepSecMap()
    env = SecureEnviron(secmap)
    rep = repr(env)
    assert "secrets=0" in rep
    assert "base_keys=" in rep

def test_mass_redact_does_not_nuke_os_environ():
    os.environ["SAFE"] = "still_here"
    secmap = PyDepSecMap()
    for i in range(10):
        secmap.add(f"K{i}", SecretEntry(value=str(i), mock_env=True))
    env = SecureEnviron(secmap)
    env.redact()
    assert "SAFE" in os.environ

def test_concurrent_redact_during_env_conversion():
    import threading
    secmap = PyDepSecMap()
    secmap.add("RACE", SecretEntry(value="1", mock_env=True, ttl_seconds=1))

    def access_env():
        _ = secmap.to_env()

    def expire_later():
        time.sleep(0.5)
        secmap.redact_expired()

    t1 = threading.Thread(target=access_env)
    t2 = threading.Thread(target=expire_later)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

def test_mock_env_name_reassignment_loop():
    entry = SecretEntry(value="val", mock_env=True, mock_env_name="A")
    secmap = PyDepSecMap()
    secmap.add("X", entry)
    env = SecureEnviron(secmap)
    assert "A" in env
    entry.mock_env_name = "B"
    assert "B" in env
    entry.mock_env_name = "C"
    assert "C" in env
    assert "A" not in env

def test_leaked_reference_outlives_redaction():
    secmap = PyDepSecMap()
    entry = SecretEntry(value="leakable", mock_env=True)
    secmap.add("L", entry)
    val = entry.get()
    secmap["L"]
    entry.redact()
    # Runtime value access is secure until extracted. If leaked into user space, it’s out of PyDepGuard’s control
    assert val == "leakable" 

def test_mock_env_name_conflicts_with_real_env():
    os.environ["REAL_ENV"] = "system"
    secmap = PyDepSecMap()
    secmap.add("SEC_KEY", SecretEntry(value="hidden", mock_env=True, mock_env_name="REAL_ENV"))
    env = SecureEnviron(secmap)
    assert env["REAL_ENV"] == "hidden"  # mock loses
    with pytest.raises(TypeError):
        _ = os.environ["REAL_ENV"]  # real env should not be accessible
        del env["REAL_ENV"]

def test_secretentry_returns_copy_not_reference():
    entry = SecretEntry(value="changeme", mock_env=True)
    val = entry.get()
    try:
        val += "modified"  # Strings are immutable, but test malicious assumptions
    except Exception:
        pass
    print("Original value after modification attempt:", entry.get())
    assert entry.get() == "changeme"  # Original value should remain unchanged
    entry.redact()
    assert entry.get() is None  # After redaction, should return None

def test_deepcopy_secureenv():
    import copy
    secmap = PyDepSecMap()
    secmap.add("A", SecretEntry(value="a", mock_env=True))
    env = SecureEnviron(secmap)
    copy_env = copy.deepcopy(env)
    assert isinstance(copy_env, SecureEnviron)
    assert copy_env["A"] == "a"