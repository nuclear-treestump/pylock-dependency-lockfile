from types import MappingProxyType
import secrets
from typing import Tuple
import sys
import time
import gc
import hmac
import os
import platform
from hashlib import blake2b
from . import net_errors as n_errors
# n_errors are errors specific to the net/ module
# These were kept separate to make maintenance easier.
# LOUD_ERRORS tells my constant_time_fail to short-circuit tracebacks.
# If LOUD_ERRORS is False, tracebacks are suppressed for security reasons.



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

def constant_time_fail(reason="Tampering suspected. Request denied.", detailed_msg: str = ""):
    if detailed_msg and n_errors.LOUD_ERRORS:
        reason = f"{detailed_msg}"
    if not n_errors.LOUD_ERRORS:
        time.sleep(1.4 + secrets.randbelow(200) / 1000 + secrets.randbits(2) * 0.5)
        sys.tracebacklimit = 0
    raise RuntimeError(reason)

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
    sys_hash = hkdf_blake2b_expand(sys_info.encode('utf-8'), info=b"sys-fingerprint", length=128).hex()
    shred_locals_by_ref(locals(), exclude=("sys_hash",))
    return sys_hash