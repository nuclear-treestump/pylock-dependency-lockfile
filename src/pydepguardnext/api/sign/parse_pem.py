# pem_parser.py
import base64
import re
from typing import Tuple

def read_pem_pkcs1(path: str) -> bytes:
    """
    Read an unencrypted PEM-encoded RSA private key (PKCS#1 or PKCS#8).
    Returns DER bytes. Actual format is detected in parser.
    """
    with open(path, "r", encoding="utf-8") as f:
        pem = f.read()

    if "ENCRYPTED" in pem:
        raise ValueError("Encrypted PEM detected. Manual OpenSSL required.")

    match = re.search(
        r"-----BEGIN RSA PRIVATE KEY-----(.*?)-----END RSA PRIVATE KEY-----",
        pem,
        re.DOTALL
    )
    pkcs8_match = re.search(
        r"-----BEGIN PRIVATE KEY-----(.*?)-----END PRIVATE KEY-----",
        pem,
        re.DOTALL
    )

    if match:
        b64 = match.group(1).strip().replace("\n", "")
        return base64.b64decode(b64)

    if pkcs8_match:
        b64 = pkcs8_match.group(1).strip().replace("\n", "")
        return base64.b64decode(b64)

    raise ValueError("PEM file does not contain a recognized RSA private key format.")


def parse_asn1_pkcs1_private_key(der: bytes):
    """
    Parse a PKCS#1 or PKCS#8 RSA private key in DER form.
    Returns (n, e, d) tuple if valid.
    Raises ValueError if malformed or incomplete.
    """
    if not isinstance(der, (bytes, bytearray)):
        raise TypeError("Expected bytes for DER input")
    if len(der) < 64:
        raise ValueError("DER too short to contain RSA private key")

    def read_length(data, offset):
        if offset >= len(data):
            raise ValueError("Unexpected end of data while reading length")
        first = data[offset]
        if first < 0x80:
            return first, 1
        n = first & 0x7F
        if offset + 1 + n > len(data):
            raise ValueError("Length field out of range")
        return int.from_bytes(data[offset+1:offset+1+n], 'big'), 1 + n

    def read_integer(data, offset):
        if offset >= len(data):
            raise ValueError("Unexpected end of data while reading INTEGER")
        if data[offset] != 0x02:
            raise ValueError(f"Expected INTEGER at offset {offset}, found 0x{data[offset]:02x}")
        length, l_len = read_length(data, offset + 1)
        start = offset + 1 + l_len
        end = start + length
        if end > len(data):
            raise ValueError("INTEGER field overflows data length")
        return int.from_bytes(data[start:end], 'big'), end

    def read_octet_string(data, offset):
        if offset >= len(data):
            raise ValueError("Unexpected end of data while reading OCTET STRING")
        if data[offset] != 0x04:
            raise ValueError(f"Expected OCTET STRING at offset {offset}, found 0x{data[offset]:02x}")
        length, l_len = read_length(data, offset + 1)
        start = offset + 1 + l_len
        end = start + length
        if end > len(data):
            raise ValueError("OCTET STRING field overflows data length")
        return data[start:end], end

    def read_sequence(data, offset):
        if offset >= len(data) or data[offset] != 0x30:
            raise ValueError("Expected SEQUENCE at offset {offset}")
        length, l_len = read_length(data, offset + 1)
        start = offset + 1 + l_len
        end = start + length
        if end > len(data):
            raise ValueError("SEQUENCE field exceeds data length")
        return start, end

    # --- Try PKCS#1 ---
    try:
        offset, seq_end = read_sequence(der, 0)
        values = []
        while offset < seq_end:
            val, offset = read_integer(der, offset)
            values.append(val)
        if len(values) != 9:
            raise ValueError("Incomplete or malformed PKCS#1 key")
        version, n, e, d, p, q, dp, dq, qi = values
        if version != 0:
            raise ValueError("Unsupported PKCS#1 version (expected 0)")
        return n, e, d
    except Exception:
        pass  # Fall through to PKCS#8
    # I have learned far too much about ASN.1 and DER parsing to be sane anymore.
    # I regret nothing.

    # --- Try PKCS#8 --- Oh dear god please work
    try:
        offset, seq_end = read_sequence(der, 0)

        # Version INTEGER
        _, offset = read_integer(der, offset)

        # AlgorithmIdentifier (SEQUENCE)
        alg_offset, alg_end = read_sequence(der, offset)
        # OID
        if der[alg_offset] != 0x06:
            raise ValueError("Expected OID for algorithm identifier")
        oid_len = der[alg_offset + 1]
        oid = der[alg_offset + 2:alg_offset + 2 + oid_len]
        rsa_oid = b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01'  # 1.2.840.113549.1.1.1
        if oid != rsa_oid:
            raise ValueError("Unsupported algorithm OID in PKCS#8")
        offset = alg_end

        # PrivateKey OCTET STRING
        pkcs1_blob, _ = read_octet_string(der, offset)
        return parse_asn1_pkcs1_private_key(pkcs1_blob)
    except Exception as e:
        raise ValueError("Invalid or unsupported RSA key format") from e

def parse_asn1_pkcs1_public_key(der: bytes) -> Tuple[int, int]:
    """
    Parse a DER-encoded PKCS#1 RSA PUBLIC KEY.
    Returns (n, e).
    """
    offset = 0

    def read_length(data, offset):
        first = data[offset]
        if first < 0x80:
            return first, 1
        n = first & 0x7F
        return int.from_bytes(data[offset+1:offset+1+n], 'big'), 1 + n

    def read_integer(data, offset):
        if data[offset] != 0x02:
            raise ValueError(f"Expected INTEGER at offset {offset}, found 0x{data[offset]:02x}")
        length, l_len = read_length(data, offset + 1)
        start = offset + 1 + l_len
        end = start + length
        return int.from_bytes(data[start:end], 'big'), end

    if der[offset] != 0x30:
        raise ValueError("Expected SEQUENCE at start of PKCS#1 DER")
    
    seq_len, len_len = read_length(der, offset + 1)
    offset += 1 + len_len

    n, offset = read_integer(der, offset)
    e, offset = read_integer(der, offset)

    return n, e

def parse_asn1_spki_public_key(der: bytes) -> Tuple[int, int]:
    """
    Parse a DER-encoded SPKI (PKCS#8-style) RSA public key.
    Returns (n, e).
    """
    offset = 0

    def read_length(data, offset):
        first = data[offset]
        if first < 0x80:
            return first, 1
        n = first & 0x7F
        return int.from_bytes(data[offset+1:offset+1+n], 'big'), 1 + n

    def read_integer(data, offset):
        if data[offset] != 0x02:
            raise ValueError(f"Expected INTEGER at offset {offset}, found 0x{data[offset]:02x}")
        length, l_len = read_length(data, offset + 1)
        start = offset + 1 + l_len
        end = start + length
        return int.from_bytes(data[start:end], 'big'), end

    def read_bit_string(data, offset):
        if data[offset] != 0x03:
            raise ValueError(f"Expected BIT STRING at offset {offset}, found 0x{data[offset]:02x}")
        length, l_len = read_length(data, offset + 1)
        start = offset + 1 + l_len
        pad_bits = data[start]
        if pad_bits != 0x00:
            raise ValueError("Expected 0 padding bits in BIT STRING")
        return data[start + 1:start + length], start + length

    if der[offset] != 0x30:
        raise ValueError("Expected SEQUENCE at start of SPKI")

    seq_len, len_len = read_length(der, offset + 1)
    offset += 1 + len_len

    # Skip AlgorithmIdentifier SEQUENCE
    if der[offset] != 0x30:
        raise ValueError("Expected SEQUENCE for algorithm ID")
    alg_len, alg_l_len = read_length(der, offset + 1)
    offset += 1 + alg_l_len + alg_len

    bitstring, _ = read_bit_string(der, offset)
    return parse_asn1_pkcs1_public_key(bitstring)



def read_pem_public_key(path: str):
    """
    Reads an RSA public key in PEM format (PKCS#1 or PKCS#8).
    Returns (n, e) as integers.
    """
    with open(path, "r", encoding="utf-8") as f:
        pem = f.read()

    pkcs1_match = re.search(
        r"-----BEGIN RSA PUBLIC KEY-----(.*?)-----END RSA PUBLIC KEY-----",
        pem, re.DOTALL
    )
    pkcs8_match = re.search(
        r"-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----",
        pem, re.DOTALL
    )

    if pkcs1_match:
        b64 = pkcs1_match.group(1).strip().replace("\n", "")
        der = base64.b64decode(b64)
        return parse_asn1_pkcs1_public_key(der)

    elif pkcs8_match:
        b64 = pkcs8_match.group(1).strip().replace("\n", "")
        der = base64.b64decode(b64)
        return parse_asn1_spki_public_key(der)

    raise ValueError("PEM file does not contain a valid RSA public key.")

