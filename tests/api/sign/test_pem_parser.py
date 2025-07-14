import pytest
import tempfile
import subprocess
import os
from pathlib import Path
import pydepguardnext.api.sign.openssl_shim as openssl_shim
import pydepguardnext.bootstrap.boot as boot
from pydepguardnext.api.sign.parse_pem import read_pem_pkcs1, parse_asn1_pkcs1_private_key, read_pem_public_key, parse_asn1_pkcs1_public_key, parse_asn1_spki_public_key
import shutil



@pytest.fixture
def gen_rsa_key_pem():
    """
    Generates a temporary unencrypted RSA key using OpenSSL.
    """
    env = os.environ.copy()
    OPENSSL_PATH = r"C:\Program Files\Git\usr\bin\openssl.exe"

    print(f"Using OpenSSL at: {OPENSSL_PATH}")
    for path in os.environ.get("PATH", "").split(os.pathsep):
        print(f"Checking path: {path}")
        if "openssl" in path.lower():
            OPENSSL_PATH = os.path.join(path, "openssl")
            break
    if not OPENSSL_PATH:
        pytest.skip("OpenSSL not found in PATH")
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as tmp:
        key_path = tmp.name
    try:
        result = subprocess.run(
            [OPENSSL_PATH, "genrsa", "-out", key_path, "2048"],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0, f"OpenSSL failed: {result.stderr}"
        yield key_path
    finally:
        if os.path.exists(key_path):
            os.remove(key_path)

def test_valid_pem_parsing(gen_rsa_key_pem):
    boot.run_boot()
    der = read_pem_pkcs1(gen_rsa_key_pem) # It doesn't care if it's PKCS#1 or PKCS#8, it just reads the PEM.
    n, e, d = parse_asn1_pkcs1_private_key(der)

    assert isinstance(n, int)
    assert isinstance(e, int)
    assert isinstance(d, int)
    assert n.bit_length() >= 2047
    assert e in (3, 65537)
    assert d > 1

def test_rejects_non_pem(tmp_path):
    boot.run_boot()
    f = tmp_path / "fake.pem"
    f.write_text("-----BEGIN FISH KEY-----\nMEOW\n-----END FISH KEY-----")
    with pytest.raises(ValueError, match="recognized RSA private key"):
        read_pem_pkcs1(str(f))

def test_rejects_corrupt_base64(tmp_path):
    boot.run_boot()
    f = tmp_path / "corrupt.pem"
    f.write_text("-----BEGIN RSA PRIVATE KEY-----\n!!!notbase64!!!\n-----END RSA PRIVATE KEY-----")
    with pytest.raises(Exception):  # base64.b64decode will raise binascii.Error
        read_pem_pkcs1(str(f))

def test_rejects_missing_fields():
    boot.run_boot()
    # Fabricate a DER blob that isn't a valid key
    invalid_der = b'\x30\x03\x02\x01\x00'  # SEQUENCE of one zero INTEGER
    with pytest.raises(ValueError, match="DER too short to contain RSA private key"):
        parse_asn1_pkcs1_private_key(invalid_der)

def test_encrypted_pem_is_rejected(tmp_path):
    boot.run_boot()
    key_path = tmp_path / "enc.pem"
    OPENSSL_PATH = r"C:\Program Files\Git\usr\bin\openssl.exe"
    result = subprocess.run(
        [OPENSSL_PATH, "genrsa", "-aes256", "-passout", "pass:test", "-out", str(key_path), "2048"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0

    with open(key_path, "r") as f:
        contents = f.read()

    assert "ENCRYPTED" in contents

    # Your parser should detect 'ENCRYPTED' string and raise early
    with pytest.raises(ValueError, match="Encrypted PEM detected"):
        read_pem_pkcs1(str(key_path))


def test_valid_pkcs1_parsing(gen_rsa_key_pem):
    der = read_pem_pkcs1(gen_rsa_key_pem)
    n, e, d = parse_asn1_pkcs1_private_key(der)
    assert isinstance(n, int)
    assert isinstance(e, int)
    assert isinstance(d, int)
    assert e == 65537


def test_rejects_truncated_der():
    with pytest.raises(ValueError, match="DER too short"):
        parse_asn1_pkcs1_private_key(b'\x30\x03\x02\x01')


def test_parse_pkcs1_public_key():
    path = "public_key.pem"
    try:
        n, e = read_pem_public_key(path)
        assert isinstance(n, int) and isinstance(e, int)
        assert e in (65537, 3, 17)
        assert n.bit_length() >= 2048
    except FileNotFoundError:
        pytest.skip(f"Public key file {path} not found. Skipping test.")


def test_parse_pkcs8_public_key():
    path = "public_key.pem"
    try:
        n, e = read_pem_public_key(path)
        assert isinstance(n, int) and isinstance(e, int)
        assert e in (65537, 3, 17)
        assert n.bit_length() >= 2048
    except FileNotFoundError:
        pytest.skip(f"Public key file {path} not found. Skipping test.")
