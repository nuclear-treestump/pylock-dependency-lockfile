"""
This module provides a function to check if an existing global private key exists.
This is used by PDG's native encryption and decryption functions.

PDG's encryption and decryption functions are used to encrypt and decrypt
sensitive data such as the private key and the manifest. It functions identically in 
spirity to asymmetric encryption, but is based on entropic key generation and does not
make use of big number math or prime numbers.

This makes my implementation of encryption and decryption much faster than traditional
asymmetric encryption, and significantly more quantum resistant than RSA or ECC.
"""

from hashlib import sha3_512, blake2b
import hmac
import tempfile
import secrets
import random
import os
import platform
import time
import json
import base64
import zlib
import sys
import math
import gc
from collections import Counter
from datetime import datetime
from datetime import timezone
from pathlib import Path
from types import MappingProxyType
from typing import Tuple

def shred_locals_by_ref(namespace: dict, exclude: Tuple[str, ...] = ()):
    for k in list(namespace.keys()):
        if k in exclude or k.startswith("__"):
            continue
        try:
            try:
                v = namespace[k]
                if isinstance(v, (bytes, bytearray)):
                    namespace[k] = secrets.token_bytes(len(v))
                elif isinstance(v, str):
                    namespace[k] = ''.join(chr(secrets.randbelow(0x110000)) for _ in range(len(v)))
                elif not isinstance(v, (MappingProxyType)):
                    namespace[k] = secrets.token_bytes(len(repr(v).encode('utf-8')))
                elif isinstance(v, MappingProxyType):
                    pass # Cannot shred MappingProxyType, skip it.
                else:
                    namespace[k] = None
            finally:
                del namespace[k]
        except Exception:
            pass
        finally:
            gc.collect()

def constant_time_fail(reason="Tampering suspected. Request denied."):
    time.sleep(1.4 + secrets.randbelow(200) / 1000 + secrets.randbits(2) * 0.5)
    sys.tracebacklimit = 0
    raise RuntimeError(reason)


# Entropy checks. While no method is perfect, a combination of these
# should be sufficient to catch most issues with the OS entropy pool.
# If any of these checks fail, we should assume the entropy pool is
# compromised and refuse to proceed. This will CTD and CTF to RIE.



# Controls the entropy level for key generation. Numbers are in bytes.

SADISM_LEVEL = MappingProxyType({
    "low": 2048,
    "medium": 4096,
    "high": 8192,
})

def hkdf_blake2b_expand(secret: bytes, info: bytes = b"", length: int = 128) -> bytes:
    """
    Perform HKDF-expand using BLAKE2b with only standard library.
    secret: input keying material (IKM)
    info: context string (e.g. "msg-ephemeral")
    length: desired output length in bytes (max 255 * hash_len)
    """
    hash_len = 64  # BLAKE2b-512 output size
    if length > 255 * hash_len:
        raise ValueError("Cannot expand to more than 16320 bytes with BLAKE2b")

    blocks = []
    prev = b""
    counter = 1

    while len(b"".join(blocks)) < length:
        h = hmac.new(secret, prev + info + bytes([counter]), blake2b)
        prev = h.digest()
        blocks.append(prev)
        counter += 1

    return b"".join(blocks)[:length]

def generate_system_fingerprint() -> str:
    if os.name == 'nt':
        # Windows
        sys_info = f"{platform.system()}-{platform.release()}-{platform.version()}-{platform.machine()}"
    elif os.name == 'posix':
        # Unix-like: Linux, macOS, etc.
        try:
            uname = os.uname()
            sys_info = f"{uname.sysname}-{uname.release}-{uname.version}-{uname.machine}"
        except AttributeError:
            # Fallback for macOS or restricted environments
            sys_info = f"{platform.system()}-{platform.release()}-{platform.version()}-{platform.machine()}"
    else:
        # Fallback for other OS types
        sys_info = f"{platform.system()}-{platform.release()}-{platform.version()}-{platform.machine()}"
    sys_hash = sha3_512(sys_info.encode()).hexdigest()
    shred_locals_by_ref(locals(), exclude=("sys_hash",))
    return sys_hash

def generate_pdgnet_global_key(project_folder: str, sadism_level = "high", force=False) -> Tuple[str, bool]:
    """
    Generate a global PDGNet key for the specified project folder.
    The key is stored in a file named 'global.key' within a '.pdgnet' directory
    inside the project folder. If the key already exists, a message is returned.

    Args:
        project_folder (str): The path to the project folder where the key should be created.
        sadism_level (str or int): The level of entropy for key generation.
    Returns:
        str: A message indicating the result of the operation.
        bool: True if a new key was created, False otherwise.
    """
    if sadism_level not in SADISM_LEVEL:
        if not isinstance(sadism_level, int):
            shred_locals_by_ref(locals())
            constant_time_fail("PDG Global Key Error")
        if int(sadism_level) < 1024:
            shred_locals_by_ref(locals())
            constant_time_fail("PDG Global Key Error")
    else:
        sadism_level = SADISM_LEVEL[sadism_level]

    pdgnet_path = Path(project_folder) / ".pdgnet"
    pdgnet_path.mkdir(parents=True, exist_ok=True)

    global_key_file = pdgnet_path / "global.key"
    if global_key_file.exists() and not force:
        message = f"Global PDGNet key already exists at {global_key_file}"
        shred_locals_by_ref(locals(), exclude=("message",))
        return message, False
    key_content_bytes = secrets.token_bytes(int(sadism_level))
    random_checks(key_content_bytes)
    key_content_b64 = base64.b64encode(key_content_bytes).decode()

    monotonic_ts = time.monotonic()
    utc_time = datetime.now(timezone.utc).isoformat()
    system_fingerprint = generate_system_fingerprint()
    random_expiry = random.randint(30, 60)  # Random expiry between 30 and 60
    key_data = {
        "keytype": "pdgnet_private",
        "keyscope": "global",
        "keyversion": "v1",
        "encrypted": False,
        "encryption_algorithm": "none",
        "encryption_difficulty": "none",
        "global_gen_time": monotonic_ts,
        "global_readable_time": utc_time,
        "global_key_name": "pdgnet-global-root",
        "global_key_content": key_content_b64,
        "expires_on": monotonic_ts + (60 * random_expiry),  # 30 to 60 minutes TTL
        "counter": 0,
        "system_fingerprint_hash": system_fingerprint,
        "global_current_rekey_time": 0.0,
        "compression": "zlib",
        "entropy_difficulty": sadism_level
    }
    key_data["ttl"] = int(key_data["expires_on"] - key_data["global_gen_time"])

    formatted_output = armor_global_key(key_data)

    output_key = (
        "----- PDG GLOBAL PRIVATE KEY START -----\n"
        f"{formatted_output}\n"
        "----- PDG GLOBAL PRIVATE KEY END -----"
    )

    with tempfile.NamedTemporaryFile('w', dir=project_folder, delete=False, encoding='utf-8') as tmpfile:
        tmpfile.write(output_key)
        tmpfile.flush()
        os.fsync(tmpfile.fileno())
        temp_path = Path(tmpfile.name)

    os.replace(temp_path, str(global_key_file))
    message = f"Global PDGNet key created at {global_key_file}"
    shred_locals_by_ref(locals(), exclude=("message",))
    return message, True

def armor_global_key(key_data: dict) -> str:
    armored_data = json.dumps(key_data, indent=2).encode()
    compressed_data = zlib.compress(armored_data, level=9)
    armored_b64 = base64.b64encode(compressed_data).decode()
    formatted_output = "\n".join([armored_b64[i:i+64] for i in range(0, len(armored_b64), 64)])
    shred_locals_by_ref(locals(), exclude=("formatted_output",))
    return formatted_output

def decode_contents(b64_content):
    """
    Decode the base64-encoded contents of a PDG global key.
    Args:
        b64_content (str): The base64-encoded content to decode.
    Returns:
        dict: The decoded key data as a dictionary.
    """
    to_decompress = base64.b64decode(b64_content)
    decompressed = zlib.decompress(to_decompress)
    decoded_dict = json.loads(decompressed.decode('utf-8'))
    shred_locals_by_ref(locals(), exclude=("decoded_dict",))
    return decoded_dict

def get_encrypted_key_data(file_path):
    raise NotImplementedError("PDG does not yet support encrypted global keys. Soon.")
    pass

def parse_pdg_global_key(file_path):
    """
    Parse a PDG global key file and return its contents as a dictionary.
    The key file is expected to be in a specific armored format.
    Args:
        file_path (str or Path): The path to the PDG global key file.
    Returns:
        dict: A dictionary containing the parsed key data.

    Note: This works on both public and private keys. This is intentional.
    """
    global_private_headerfooters = [
        "----- PDG GLOBAL PRIVATE KEY START -----",
        "----- PDG GLOBAL PRIVATE KEY END -----",
    ]
    global_public_headerfooters = [
        "----- PDG GLOBAL PUBLIC KEY START -----",
        "----- PDG GLOBAL PUBLIC KEY END -----",
    ]
    with open(file_path, 'r') as f:
        lines = f.read().splitlines()
    
    # Extract the base64 content between the headers
    if not lines:
        shred_locals_by_ref(locals())
        constant_time_fail("PDG Global Key Error")
    check_encrypted = bool("ENCRYPTED" in lines[0])
    check_public = bool(lines[0] in global_public_headerfooters and lines[-1] in global_public_headerfooters)
    check_private = bool(lines[0] in global_private_headerfooters and lines[-1] in global_private_headerfooters)
    b64_content = ""
    if check_encrypted:
        shred_locals_by_ref(locals())
        get_encrypted_key_data(file_path)
        constant_time_fail("PDG Not Yet Implemented: Encrypted Global Keys")
    if not check_private and not check_public:
        shred_locals_by_ref(locals())
        constant_time_fail("PDG Global Key Error")
    if check_public or check_private:
        b64_content = ''.join(lines[1:-1])
    decoded_dict = decode_contents(b64_content)
    return decoded_dict

def check_global_key_exists(project_folder: str) -> bool:
    """
    Check if the global PDGNet key exists.
    Args:
        project_folder (str): The path to the project folder where the key should be checked.
    Returns:
        bool: True if the key exists, False otherwise.
    """
    global_key_path = Path(project_folder) / ".pdgnet" / "global.key"
    exists = global_key_path.exists()
    shred_locals_by_ref(locals(), exclude=("exists",))
    return exists

def read_global_key(project_folder: str) -> str:
    global_key_path = Path(project_folder) / ".pdgnet" / "global.key"
    if not global_key_path.exists():
        shred_locals_by_ref(locals())
        constant_time_fail("PDG Global Key Error")
    gkp_txt = global_key_path.read_text()
    shred_locals_by_ref(locals(), exclude=("gkp_txt",))
    return gkp_txt

def generate_global_key_if_missing(project_folder: str, sadism_level: str = "high") -> bool:
    """
    Generate a new global PDGNet key if one does not already exist.
    Args:
        project_folder (str): The path to the project folder where the key should be created.
    Returns:
        bool: True if a new key was created, False if the key already exists.
    """
    if check_global_key_exists(project_folder):
        shred_locals_by_ref(locals())
        return True
    _, created = generate_pdgnet_global_key(project_folder, sadism_level)
    if not created:
        # If the key was not created, check again if it exists
        if check_global_key_exists(project_folder):
            shred_locals_by_ref(locals())
            return True
        else:
            # If it still doesn't exist, raise an error
            shred_locals_by_ref(locals())
            constant_time_fail("PDG Global Key Error")
    shred_locals_by_ref(locals(), exclude=("created",))
    return created

def revoke_global_key(project_folder: str) -> str:
    """
    Revoke the global PDGNet key.
    This function deletes the existing global key file and generates a new one.
    Args:
        project_folder (str): The path to the project folder where the key should be revoked.
    Returns:
    """
    global_key_path = Path(project_folder) / ".pdgnet" / "global.key"
    if global_key_path.exists():
        gkey = parse_pdg_global_key(global_key_path)
        sadism = gkey.get("entropy_difficulty", "high")
        global_key_path.unlink()
        generate_global_key_if_missing(project_folder, sadism_level=sadism)
        message = f"Global key at {global_key_path} has been revoked and replaced."
        shred_locals_by_ref(locals(), exclude=("message",))
        return message
    message = f"No global key found at {global_key_path} to revoke."
    shred_locals_by_ref(locals(), exclude=("message",))
    return message

def repack_key(parsed_key: dict, file_path: Path) -> None:
    """
    Repack the parsed PDG global key into the expected format.
    Args:
        parsed_key (dict): The parsed key data.
        file_path (Path): The path to the file where the repacked key should be saved.
    """
    formatted_output = armor_global_key(parsed_key)

    output_key = (
        "----- PDG GLOBAL PRIVATE KEY START -----\n"
        f"{formatted_output}\n"
        "----- PDG GLOBAL PRIVATE KEY END -----"
    )

    with tempfile.NamedTemporaryFile('w', dir=file_path.parent, delete=False, encoding='utf-8') as tmpfile:
        tmpfile.write(output_key)
        tmpfile.flush()
        os.fsync(tmpfile.fileno())
        temp_path = Path(tmpfile.name)
    os.replace(temp_path, file_path)
    shred_locals_by_ref(locals())

def repack_public_key(parsed_key: dict, file_path: Path) -> None:
    """
    Repack the parsed PDG global public key into the expected format.
    Args:
        parsed_key (dict): The parsed key data.
        file_path (Path): The path to the file where the repacked key should be saved.
    """
    formatted_output = armor_global_key(parsed_key)

    output_key = (
        "----- PDG GLOBAL PUBLIC KEY START -----\n"
        f"{formatted_output}\n"
        "----- PDG GLOBAL PUBLIC KEY END -----"
    )

    with tempfile.NamedTemporaryFile('w', dir=file_path.parent, delete=False, encoding='utf-8') as tmpfile:
        tmpfile.write(output_key)
        tmpfile.flush()
        os.fsync(tmpfile.fileno())
        temp_path = Path(tmpfile.name)
    os.replace(temp_path, file_path)
    shred_locals_by_ref(locals())


def rekey_global_key(project_folder: str) -> bool:
    """
    Rekey the global PDGNet key.
    This is an operation that randomly modifies a portion of the existing key
    to create a new key. It does not delete the existing key file, but modifies it and 
    updates the metadata to reflect the rekeying operation.
    It also increments the counter and sets a new expiry time.
    Args:
        project_folder (str): The path to the project folder where the key should be rekeyed.
    """
    global_key_path = Path(project_folder) / ".pdgnet" / "global.key"
    if global_key_path.exists():
        parsed_key = parse_pdg_global_key(global_key_path)
        if parsed_key.get("keytype") == "pdgnet_private" and parsed_key.get("keyscope") == "global":
            old_entropy = base64.b64decode(parsed_key["global_key_content"])
            old_entropy = bytearray(old_entropy)
            key_len = len(old_entropy)
            injection_size = max(32, key_len // 128)
            max_offset = len(old_entropy) - injection_size
            if max_offset <= 0:
                shred_locals_by_ref(locals())
                constant_time_fail("PDG Global Key Error")
            offset = secrets.randbelow(max_offset + 1)
            old_entropy[offset:offset+injection_size] = secrets.token_bytes(injection_size)
            random_checks(old_entropy)
            parsed_key["global_key_content"] = base64.b64encode(old_entropy).decode()
            parsed_key["counter"] += 1
            random_expiry = random.randint(30, 60)
            parsed_key["global_current_rekey_time"] = time.monotonic()
            parsed_key["invalid_on"] = time.monotonic() + (60 * random_expiry)
        repack_key(parsed_key, global_key_path)
        shred_locals_by_ref(locals(), exclude=())
        return True
    else:
        created = generate_global_key_if_missing(project_folder)
        if created:
            message = f"Global key did not exist and was created at {global_key_path}"
            shred_locals_by_ref(locals(), exclude=("message",))
            return True
        else:
            shred_locals_by_ref(locals())
            constant_time_fail("PDG Global Key Error")
            return False
        
def get_global_public_key(project_folder: str) -> bool:
    """
    Get the global PDGNet public key.
    Args:
        project_folder (str): The path to the project folder where the key should be read.
    Returns:
        str: The global PDGNet public key.
    """
    global_key_path = Path(project_folder) / ".pdgnet" / "global.key"
    if not global_key_path.exists():
        shred_locals_by_ref(locals())
        constant_time_fail("PDG Global Key Error")
    parsed_key = parse_pdg_global_key(global_key_path)
    if parsed_key.get("keytype") != "pdgnet_private" or parsed_key.get("keyscope") != "global":
        shred_locals_by_ref(locals())
        constant_time_fail("PDG Global Key Error")
    public_key_bytes = base64.b64decode(parsed_key["global_key_content"])
    system_fingerprint = parsed_key.get("system_fingerprint_hash", "")
    public_key = hkdf_blake2b_expand((public_key_bytes), info=system_fingerprint.encode(), length=128)
    public_key = public_key.hex()
    expires_on = parsed_key.get("expires_on")
    if expires_on < time.monotonic():
        shred_locals_by_ref(locals())
        constant_time_fail("PDG Global Key Error")
    ratchet = parsed_key.get("counter")
    pubkey_key = b'PUBKEY_GLOBAL_V1' + b':' + str(ratchet).encode() + b':' + str(expires_on).encode() + b':' + public_key.encode()
    pubkey_obj = {
        "keytype": "pdgnet_public",
        "keyscope": "global",
        "keyversion": "v1",
        "public_key": base64.b64encode(pubkey_key).decode(),
        "ratchet": ratchet,
        "expires_on": expires_on,
        "fingerprint": parsed_key.get("system_fingerprint_hash"),
        "ttl": int(expires_on - time.monotonic()),
        "compression": "zlib"
    }
    repack_public_key(pubkey_obj, global_key_path.parent / "global.pub")
    shred_locals_by_ref(locals(), exclude=("pubkey_key",))
    return True

def check_public_key_expiry(project_folder: str) -> bool:
    """
    Check if the global PDGNet public key has expired.
    Args:
        project_folder (str): The path to the project folder where the key should be checked.
    Returns:
        bool: True if the key has expired, False otherwise.
    """
    global_key_path = Path(project_folder) / ".pdgnet" / "global.pub"
    if not global_key_path.exists():
        shred_locals_by_ref(locals())
        constant_time_fail("PDG Global Key Error")
    parsed_key = parse_pdg_global_key(global_key_path)
    expires_on = parsed_key.get("expires_on")
    if parsed_key.get("keytype") != "pdgnet_public":
        shred_locals_by_ref(locals())
        constant_time_fail("PDG Global Key Error")
    if parsed_key.get("keyscope") != "global":
        shred_locals_by_ref(locals())
        constant_time_fail("PDG Global Key Error")
    if expires_on < time.monotonic():
        shred_locals_by_ref(locals())
        return True
    else:
        shred_locals_by_ref(locals())
        return False


'''
The process is this.
1. Parent Process spins up.
2. Parent process produces 2048 bytes entropy and makes a private key just like how Global Key generation works.
3. Parent process generates a UUID for itself.
4. Parent Process generates a public key using the following:
- global pub key (it needs to grab this through PDG_INIT to global key store)
- parent entropy blob
- timestamp monotonic
- parent UUID
- 32 byte entropy (just to be sure)
The parent process is now ready to receive requests.

1. Child process spins up
2. Child process needs a way to query the parent process.
3. PDG_INIT sent to parent process
4. PDG_INIT is a json blob with:
{
    "actionuuid": "cccc:PDG_INIT:<child uuid>",
    "timestamp": "<monotonic timestamp>",
    "dest": "00FF:<parent_uuid>",
    "op": "init"
}
5. Parent process receives PDG_INIT, validates it, and responds with PDG_ACK
6. PDG_ACK is a json blob with:
{
    "actionuuid": "00FF:PDG_ACK:<parent uuid>",
    "dest": "cccc:<child uuid>",
    "pubkey": "<base64 encoded parent public key>",
    "timestamp": "<monotonic timestamp>",
    "challenge": "<base64 encoded 32 byte challenge>",
    "op": "ack",
    "nonce": "<base64 encoded 32 byte nonce (for future use)>"
}
7. Parent saves the challenge for the next step.
8. Child process receives PDG_ACK, validates it, and stores the public key for future use.
9. Child Process generates its own entropy blob (2048 bytes)
10. Child Process generates its own public key using the following:
- parent pub key (from PDG_ACK) (now the child's key is chained to the parent's key.)
- child entropy blob
- timestamp monotonic
- child UUID
- 32 byte entropy (just to be sure)
11. Child process saves the challenge for the next step.
12. Child process sends the following to the parent process:
{
    "actionuuid": "cccc:PDG_PUBEX:<child uuid>",
    "dest": "00FF:<parent uuid>",
    "timestamp": "<monotonic timestamp>",
    "op": "pubex",
    "pubkey": "<base64 encoded child public key>",
}

13. Parent process receives PDG_PUBEX, validates it and consumes the public key.
14. Parent process generates a proposed seed using HKDF-BLAKE2b-Expand with the following:
- child pub key
- parent entropy blob
- timestamp monotonic
- parent UUID
- 32 byte entropy (just to be sure)
This is the parent's lineage key.
15. Parent process sends the following to the child process:
{
    "actionuuid": "00FF:PDG_SEED:<parent uuid>",
    "dest": "cccc:<child uuid>",
    "timestamp": "<monotonic timestamp>",
    "op": "seed",
    "seed": "<base64 encoded proposed seed>",
}
16. Child process receives PDG_SEED, validates it and consumes the seed.
17. Child process generates a challenge response using HKDF-BLAKE2b-Expand with the following:
- proposed seed (from parent)
- child pubkey
- child challenge (from PDG_ACK)
- 32 byte nonce (from PDG_ACK)
17b. Child process generates its own key using HKDF-BLAKE2b-Expand with the following:
- Child entropy blob
- Parent pubkey (from PDG_ACK)
- timestamp monotonic
- child UUID
- 32 byte entropy (just to be sure)
This key is saved for the next ratchet and is the child lineage key.
18. Child process sends the following to the parent process:
{
    "actionuuid": "cccc:PDG_HELLO:<child uuid>",
    "dest": "00FF:<parent uuid>",
    "timestamp": "<monotonic timestamp from generation of challenge response>",
    "op": "challenge",
    "nonce": "<base64 encoded 32 byte nonce>",
    "msg": {
        "challenge_response": "<base64 encoded encrypted challenge response encrypted with the derived key from parent seed>",
        "next_key": "<base64 encoded next proposed key (HKDF-BLAKE2b-Expand of the CHILD'S lineage key + 32 byte entropy for ratcheting)>",
        "mut_challenge": "<base64 encoded child challenge (from PDG_ACK)>",
    },
    "hmac": "<base64 encoded HMAC-blake2b of the envelope using the derived key as key + the nonce>",
}
Everything in "msg" is encrypted with the derived key from the proposed seed.
The challenge response is validated by decrypting it with a key derived from the following on the parent side:
- proposed seed saved on parent side
- child pubkey (from PDG_PUBEX)
- child challenge (from PDG_ACK)
- 32 byte nonce (saved from previous step)
If the challenge response is valid, the parent process responds with PDG_HOWAREYOU and generates its own challenge response using HKDF-BLAKE2b-Expand with the following:
- proposed seed (from child)
- parent pubkey (already known to parent)
- mut_challenge (from PDG_HELLO)
- nonce (from PDG_HELLO)
Parent also generates its own next_key using HKDF-BLAKE2b-Expand with the following:
- parent lineage key (from previous step)
- 32 byte entropy (just to be sure)
19. Parent process sends the following to the child process encrypted with the next_key from child message:
{
    "actionuuid": "00FF:PDG_HOWAREYOU:<parent uuid>",
    "dest": "cccc:<child uuid>",
    "timestamp": "<monotonic timestamp>",
    "op": "good",
    "nonce": "<base64 encoded 32 byte nonce (newly generated)>",
    "msg": {
        "challenge_response": "<base64 encoded challenge response (from PDG_HELLO)>",
        "next_key": "<base64 encoded encrypted next parent key>",
    },
    "hmac": "<base64 encoded HMAC-blake2b of the envelope using the derived key as key + the nonce>",
}
Once again, everything in "msg" is encrypted with the child's next_key from previous message.
20. Child process receives PDG_HOWAREYOU, validates it and consumes the challenge response.
21. Child process validates the challenge response by decrypting it with a key derived from the following on the child side:
- child lineage key (from previous step)
- parent pubkey (from PDG_ACK)
- mutchallenge (from PDG_HELLO)
- 32 byte nonce (from PDG_HOWAREYOU)
22. If the challenge response is valid, the child process is now authenticated and can send encrypted messages to the parent process using the derived key from the proposed parent seed.
23. The parent process can send encrypted messages to the child process using the derived key from the proposed child seed.
24. The child sends back PDG_GOOD_ACK to acknowledge the parent process's challenge response and confirm the secure channel is established.
{
    "actionuuid": "cccc:PDG_GOOD_ACK:<child uuid>",
    "dest": "00FF:<parent uuid>",
    "timestamp": "<monotonic timestamp>",
    "op": "good_ack",
    "nonce": "<base64 encoded 32 byte nonce (newly generated)>",
    "msg": {
        "ack": "ok",
        "next_key": "<base64 encoded encrypted next child key>",
        "session_id": "<base64 encoded session id (random 16 bytes)>",
        "session_ratchet": 0,
        },
    "hmac": "<base64 encoded HMAC-blake2b of the envelope using the derived key as key + the nonce>",
}
Everything in "msg" is encrypted with the parent's next_key from previous message.
25. Optionally, symmetrical keys can be derived after this point for faster encryption/decryption of messages, but this is not required or currently implemented.
26. Every next message will have a next_key field that is used to ratchet the key for the next message. The only way to decrypt it is to have the previous key from the other's lineage key.
27. Both sides will ratchet each other's keys after every successful message exchange.

'''