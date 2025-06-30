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
