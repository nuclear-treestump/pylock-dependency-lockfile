from pydepguardnext.api.seal.seal import generate_key, derive_nonce, seal_manifest, unseal_manifest
from pydepguardnext.api.errors import RuntimeInterdictionError
import pytest
from base64 import b64encode, b64decode
import secrets

def test_seal_unseal_roundtrip():
    key = generate_key()
    nonce = derive_nonce()
    original = {"hello": "world"}
    sealed, hmac_key = seal_manifest(original.copy(), key, nonce, context="test_context")
    unsealed = unseal_manifest(sealed, key, hmac_key)

    assert unsealed["hello"] == "world"
    assert unsealed["context"] == "test_context"
    assert "timestamp" in unsealed

def test_hmac_tamper_detection_raises():
    key = generate_key()
    nonce = derive_nonce()
    data, hmac_key = seal_manifest({"val": "x"}, key, nonce, context="x")
    data["tag"] = "00" * 32  # Lol

    with pytest.raises(RuntimeInterdictionError):
        unseal_manifest(data, key, hmac_key)

def test_wrong_key_fails():
    key = generate_key()
    nonce = derive_nonce()
    sealed, hmac_key = seal_manifest({"val": "x"}, key, nonce, context="fail")

    bad_key = generate_key()
    with pytest.raises(Exception):
        unseal_manifest(sealed, bad_key, hmac_key)

def test_wrong_hmac_key_rejected():
    key = generate_key()
    nonce = derive_nonce()
    sealed, hmac_key = seal_manifest({"safe": True}, key, nonce, context="fail")

    wrong_hmac = generate_key()
    with pytest.raises(RuntimeInterdictionError):
        unseal_manifest(sealed, key, wrong_hmac)

def test_empty_data_manifest():
    key = generate_key()
    nonce = derive_nonce()
    sealed, hmac_key = seal_manifest({}, key, nonce, context="empty")
    unsealed = unseal_manifest(sealed, key, hmac_key)

    assert unsealed["context"] == "empty"
    assert isinstance(unsealed["timestamp"], float)

def test_malformed_sealed_payload():
    key = generate_key()
    hmac_key = generate_key()
    with pytest.raises(KeyError):
        unseal_manifest({"blob": "abcd"}, key, hmac_key)  # missing nonce/tag

def test_corrupted_base64_data():
    key = generate_key()
    nonce = derive_nonce()
    sealed, hmac_key = seal_manifest({"x": "y"}, key, nonce, context="corrupt")
    sealed["blob"] = "!!!!not_base64!!!!"

    with pytest.raises(Exception):
        unseal_manifest(sealed, key, hmac_key)

# Harder tests

def test_unseal_with_random_junk():
    key = generate_key()
    hmac_key = generate_key()
    sealed = {
        "nonce": b64encode(secrets.token_bytes(32)).decode(),
        "blob": b64encode(secrets.token_bytes(64)).decode(),
        "tag": "deadbeef" * 8  # 64 hex chars
    }

    with pytest.raises(RuntimeInterdictionError):
        unseal_manifest(sealed, key, hmac_key)

def test_tag_swap_between_manifests():
    key = generate_key()
    nonce1 = derive_nonce()
    nonce2 = derive_nonce()

    sealed1, hmac_key1 = seal_manifest({"a": 1}, key, nonce1, "ctx1")
    sealed2, hmac_key2 = seal_manifest({"b": 2}, key, nonce2, "ctx2")

    sealed2["tag"] = sealed1["tag"]  # maliciously yoink tag

    with pytest.raises(RuntimeInterdictionError):
        unseal_manifest(sealed2, key, hmac_key2)

def test_truncated_encrypted_blob():
    key = generate_key()
    nonce = derive_nonce()
    sealed, hmac_key = seal_manifest({"msg": "hello"}, key, nonce, context="cut")

    sealed["blob"] = sealed["blob"][:10]  # cut it short

    with pytest.raises(Exception):
        unseal_manifest(sealed, key, hmac_key)

def test_non_base64_input_fails():
    key = generate_key()
    hmac_key = generate_key()
    sealed = {
        "nonce": "%%%INVALID%%%",
        "blob": "!!!!",
        "tag": "abcd" * 16
    }

    with pytest.raises(Exception):
        unseal_manifest(sealed, key, hmac_key)


def test_replay_does_not_leak_info():
    key = generate_key()
    nonce = derive_nonce()
    sealed, hmac_key = seal_manifest({"user": "admin"}, key, nonce, context="replay")

    # Reuse same sealed data multiple times
    for _ in range(5):
        out = unseal_manifest(sealed, key, hmac_key)
        assert out["user"] == "admin"
