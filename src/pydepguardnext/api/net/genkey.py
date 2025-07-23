from types import MappingProxyType
from .key_utils import shred_locals_by_ref, constant_time_fail, hkdf_blake2b_expand, generate_system_fingerprint
from .entropy_utils import random_checks
from .memoryhandler import SecureMemory
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

SADISM_LEVEL = MappingProxyType({
    "low": 2048,
    "medium": 4096,
    "high": 8192,
})


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