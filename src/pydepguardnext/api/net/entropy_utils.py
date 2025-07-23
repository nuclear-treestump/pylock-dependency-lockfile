from collections import Counter
import math
from hashlib import sha3_512
from pathlib import Path
import tempfile
import hmac
from pydepguardnext.api.net.key_utils import shred_locals_by_ref, constant_time_fail

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
        constant_time_fail("Entropy Error", "Entropy Error: Zeroed entropy. Execution halted.")
    if entropy_is_patterned(data):
        shred_locals_by_ref(locals())
        constant_time_fail("Entropy Error", "Entropy Error: Data is patterned. Execution halted.")
    if detect_replay(data):
        shred_locals_by_ref(locals())
        constant_time_fail("Entropy Error", "Entropy Error: Data sha3-512 hash matches previous entropic state. Possible replay attack. Execution halted.")
    entropy = shannon_entropy(data)
    if entropy < entropy_threshold:
        shred_locals_by_ref(locals())
        constant_time_fail("Entropy Error", "Entropy Error: Shannon entropy check failed or is below threshold. Execution halted.")
    shred_locals_by_ref(locals())
    return True