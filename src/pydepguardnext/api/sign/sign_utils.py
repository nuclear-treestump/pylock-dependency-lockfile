from typing import Tuple
import os
import sys
import time
import secrets
import hmac
import tempfile
from hashlib import sha3_512
from pathlib import Path
from pydepguardnext.api.errors import RuntimeInterdictionError
from collections import Counter
import math
def shred_locals_by_ref(namespace: dict, exclude: Tuple[str, ...] = ()):
    for k in list(namespace.keys()):
        if k in exclude or k.startswith("__"):
            continue
        try:
            namespace[k] = os.urandom(len(namespace[k]))
            namespace[k] = None
        except Exception:
            pass
        finally:
            import gc
            gc.collect()

def constant_time_fail(reason="Tampering suspected. Request denied."):
    time.sleep(1.4 + secrets.randbelow(200) / 1000 + secrets.randbits(2) * 0.5)
    sys.tracebacklimit = 0
    raise RuntimeInterdictionError(reason)


# Entropy checks. While no method is perfect, a combination of these
# should be sufficient to catch most issues with the OS entropy pool.
# If any of these checks fail, we should assume the entropy pool is
# compromised and refuse to proceed. This will CTD and CTF to RIE.

def entropy_is_zero(data: bytes) -> bool:
    return all(b == 0 for b in data)

def entropy_is_patterned(data: bytes) -> bool:
    return data == data[:len(data)//2] * 2 or len(set(data)) <= 2

def detect_replay(data: bytes, cache_file=".entropycache") -> bool:
    current_hash = sha3_512(data).digest()
    cache_path = Path(tempfile.gettempdir()) / cache_file

    if cache_path.exists():
        old_hash = cache_path.read_bytes()
        if hmac.compare_digest(current_hash, old_hash):
            return True  # Entropy pool is potentially deterministic/replayed. PANIC.

    cache_path.write_bytes(current_hash)
    return False


def shannon_entropy(data: bytes) -> float:
    counter = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counter.values())

def random_checks(data: bytes, entropy_threshold: float = 7.8) -> bool:
    if entropy_is_zero(data):
        shred_locals_by_ref(locals())        
        constant_time_fail("Entropy Error")
    if entropy_is_patterned(data):
        shred_locals_by_ref(locals())        
        constant_time_fail("Entropy Error")
    if detect_replay(data):
        shred_locals_by_ref(locals())        
        constant_time_fail("Entropy Error")
    entropy = shannon_entropy(data)
    if entropy < entropy_threshold:
        shred_locals_by_ref(locals())
        constant_time_fail("Entropy Error")
    shred_locals_by_ref(locals())
    return True


