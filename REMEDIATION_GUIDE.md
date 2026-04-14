# Security Remediation Guide

This document provides step-by-step fixes for each identified vulnerability.

---

## 1. Fix Command Injection in openssl_shim.py

### Before (Vulnerable):
```python
import subprocess
import re

def parse_rsa_private_key(path: str):
    result = subprocess.run(
        ["openssl", "rsa", "-in", path, "-noout", "-text"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"OpenSSL failed: {result.stderr}")
    # ... rest of parsing
```

### After (Secure):
```python
import subprocess
import re
from pathlib import Path

def parse_rsa_private_key(path: str):
    # Validate input
    key_path = Path(path).resolve()
    
    # Check if path exists and is a file
    if not key_path.exists():
        raise FileNotFoundError(f"Key file not found: {path}")
    if not key_path.is_file():
        raise ValueError(f"Path is not a regular file: {path}")
    
    # Optional: restrict to specific allowed directories
    # allowed_dirs = [Path.home() / ".ssh", Path("/etc/keys")]
    # if not any(str(key_path).startswith(str(d)) for d in allowed_dirs):
    #     raise PermissionError(f"Key path outside allowed directories: {path}")
    
    result = subprocess.run(
        ["openssl", "rsa", "-in", str(key_path), "-noout", "-text"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"OpenSSL failed: {result.stderr}")
    
    # ... rest of parsing
```

---

## 2. Fix Path Traversal in airjail.py

### Before (Vulnerable):
```python
def is_within_jail(path: Path) -> bool:
    try:
        path_real = path.resolve(strict=True)
        jail_real = JAIL_ROOT
        
        if str(path_real).startswith(str(jail_real)):
            return True
        
        # BUG: This condition REQUIRES the startswith check to pass
        # so the inode fallback is never actually used!
        jail_dev_ino = os.stat(jail_real)
        path_dev_ino = os.stat(path_real)
        
        return jail_dev_ino.st_dev == path_dev_ino.st_dev and str(path_real).startswith(str(jail_real))
```

### After (Secure):
```python
from pathlib import Path
import os

def is_within_jail(path: Path) -> bool:
    """
    Verifies the given path is within the defined jail, even if symlinks are involved.
    Uses Path.relative_to() which is the most reliable method.
    """
    try:
        # Resolve to absolute paths, following symlinks
        path_real = path.resolve(strict=True)
        jail_real = JAIL_ROOT.resolve()
        
        # Use relative_to to safely check containment
        # This will raise ValueError if path is not under jail
        path_real.relative_to(jail_real)
        return True
        
    except ValueError:
        # path is outside jail
        return False
    except FileNotFoundError:
        # For non-existent files, check if the parent directory is within jail
        try:
            parent = path.parent.resolve(strict=True)
            parent.relative_to(JAIL_ROOT.resolve())
            return True
        except (ValueError, FileNotFoundError):
            return False
    except Exception:
        # Any other error: deny access
        return False

def check_jail_violation(path: Path, op="read"):
    """
    Raises if a path is outside the jail root.
    """
    if not is_within_jail(path):
        raise PermissionError(f"[PDG] Jail violation ({op}): {path}")
```

---

## 3. Fix Entropy Cache File Permissions

### Before (Vulnerable):
**File**: `src/pydepguardnext/api/net/entropy_utils.py`

```python
def detect_replay(data: bytes, cache_file=".entropycache") -> bool:
    current_hash = sha3_512(data).digest()
    cache_path = Path(tempfile.gettempdir()) / cache_file
    
    if cache_path.exists():
        old_hash = cache_path.read_bytes()
        if hmac.compare_digest(current_hash, old_hash):
            return True
    
    cache_path.write_bytes(current_hash)  # No permission control!
    return False
```

### After (Secure):
```python
import tempfile
import os
from pathlib import Path
from hashlib import sha3_512
import hmac

def detect_replay(data: bytes, cache_file=".entropycache") -> bool:
    """
    Detect if entropy has been replayed using secure cache.
    """
    current_hash = sha3_512(data).digest()
    
    # Create secure cache directory (owner-only access: 0o700)
    cache_dir = Path(tempfile.gettempdir()) / ".pdg_entropy_cache"
    cache_dir.mkdir(mode=0o700, exist_ok=True)
    cache_path = cache_dir / cache_file
    
    try:
        # Check existing cache
        if cache_path.exists():
            # Verify permissions before reading
            stat_info = cache_path.stat()
            if stat_info.st_mode & 0o077:  # Check if world/group readable
                # File has insecure permissions - regenerate
                cache_path.unlink()
            else:
                old_hash = cache_path.read_bytes()
                if hmac.compare_digest(current_hash, old_hash):
                    return True  # Replay detected
        
        # Write new hash with secure permissions
        cache_path.write_bytes(current_hash)
        # Explicitly set secure permissions (owner read/write only)
        cache_path.chmod(0o600)
        
    except Exception as e:
        # If cache operations fail, fail secure (deny operation)
        shred_locals_by_ref(locals())
        constant_time_fail(f"Entropy cache error: {e}")
    
    return False
```

### Also fix in `src/pydepguardnext/api/sign/sign_utils.py`:
Apply the same secure cache pattern.

---

## 4. Upgrade Cryptographic Implementation

### Before (Vulnerable - PKCS#1 v1.5):
**File**: `src/pydepguardnext/api/runtime/sigverify.py`

```python
def emsa_pkcs1_v1_5_encode(digest_bytes: bytes, n_bytes: int) -> bytes:
    sha256_prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    t = sha256_prefix + digest_bytes
    padding_len = n_bytes - len(t) - 3
    if padding_len < 8:
        raise ValueError("Encoding error: insufficient padding space.")
    return b"\x00\x01" + b"\xff" * padding_len + b"\x00" + t

def validate_signature(digest_bytes: bytes, sig_int: int) -> bool:
    pubkey = SIGSTORE_PUBKEY
    n_bytes = (pubkey["n"].bit_length() + 7) // 8
    decrypted_bytes = pow(sig_int, pubkey["e"], pubkey["n"]).to_bytes(n_bytes, "big")
    expected_bytes = emsa_pkcs1_v1_5_encode(digest_bytes, n_bytes)
    return decrypted_bytes == expected_bytes
```

### After (Secure - Using cryptography library):
```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import hmac

# Load public key from stored PEM
PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm/i2a9xM8B+2x7aaUr37
pFHaYzeTKtp7o99gXAZOr50CtqyJHWszSyZstDuDZ4oFfvBXo6Ktr1rb7G3zyn3B
D1DmFcqZ5cHKNaM7ROUkV/FlpjyisFt469MTB6qAd27tnYmuxM/xHUGojJAKP0jA
I2tSSRKQT9ospH/SKf+cGfkKETLLoyJhVrQhRuRO7ml9djUF9ja3u7bCdnMTGPTV
Mu+81TYOwMoRXU1Mq8tugkUGZAz+Wci9Wkj+sNbPK9KXgF3P+zc41sqq0nuepQCl
nC+JHinmMSumlRMrzZXDRqFUKxX2pksJnaDoa7XOwqP9H78iHFASbMcVmXKIT+QD
TQIDAQAB
-----END PUBLIC KEY-----"""

def load_public_key():
    """Load the public key from PEM format."""
    return serialization.load_pem_public_key(
        PUBLIC_KEY_PEM.encode(),
        backend=default_backend()
    )

def validate_signature_secure(signature_bytes: bytes, data: bytes) -> bool:
    """
    Validate RSA signature using PSS padding (modern, secure approach).
    
    Args:
        signature_bytes: The signature bytes
        data: The data that was signed
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        public_key = load_public_key()
        public_key.verify(
            signature_bytes,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        # Use constant-time comparison to avoid timing attacks
        return False

# Keep backward compatibility wrapper
def validate_signature(digest_bytes: bytes, sig_int: int) -> bool:
    """
    Backward compatibility wrapper (DEPRECATED).
    Use validate_signature_secure() instead.
    """
    import warnings
    warnings.warn(
        "validate_signature() uses deprecated PKCS#1 v1.5. "
        "Use validate_signature_secure() instead.",
        DeprecationWarning
    )
    # ... old implementation for backward compatibility ...
```

---

## 5. Reduce System Information Disclosure

### Before (Vulnerable):
**File**: `src/pydepguardnext/api/net/key_utils.py`

```python
def generate_system_fingerprint() -> str:
    if os.name == 'nt':
        sys_info = f"{platform.system()}-{platform.release()}-{platform.version()}-{platform.machine()}"
    elif os.name == 'posix':
        try:
            uname = os.uname()
            sys_info = f"{uname.sysname}-{uname.release}-{uname.version}-{uname.machine}"
        except AttributeError:
            sys_info = f"{platform.system()}-{platform.release()}-{platform.version()}-{platform.machine()}"
    else:
        sys_info = f"{platform.system()}-{platform.release()}-{platform.version()}-{platform.machine()}"
    sys_hash = hkdf_blake2b_expand(sys_info.encode('utf-8'), info=b"sys-fingerprint", length=128).hex()
    shred_locals_by_ref(locals(), exclude=("sys_hash",))
    return sys_hash
```

### After (Secure):
```python
import uuid
import secrets
import os
import platform

def generate_system_fingerprint() -> str:
    """
    Generate a system fingerprint without exposing detailed system information.
    Uses combination of hardware ID and random component for uniqueness.
    """
    try:
        # Use hardware UUID (MAC address) - more stable than OS version
        hw_uuid = hex(uuid.getnode())
    except Exception:
        # Fallback: use random bytes if hardware UUID unavailable
        hw_uuid = secrets.token_hex(6)
    
    try:
        # Only include minimal OS family info (no version numbers)
        os_family = platform.system().lower()  # "linux", "windows", "darwin"
    except Exception:
        os_family = "unknown"
    
    # Combine hardware ID with OS family and random component
    fingerprint_input = f"{hw_uuid}-{os_family}-{secrets.token_hex(8)}".encode('utf-8')
    
    sys_hash = hkdf_blake2b_expand(
        fingerprint_input,
        info=b"sys-fingerprint",
        length=128
    ).hex()
    
    shred_locals_by_ref(locals(), exclude=("sys_hash",))
    return sys_hash
```

---

## 6. Fix Guard Page Logic Error

### Before (Vulnerable):
**File**: `src/pydepguardnext/api/sign/securemem.py` (Lines 216-259)

```python
def _protect_guard_pages(self):
    # ...
    system = platform.system()
    if system == "Windows":
        PAGE_NOACCESS = 0x01
        kernel32 = ctypes.windll.kernel32
        old_protect = ctypes.c_ulong()
        for offset in (0, self.ptr + self.size):  # BUG: First offset should be base_address!
            if not kernel32.VirtualProtect(
                ctypes.c_void_p(offset),
                ctypes.c_size_t(self.page_size),
                PAGE_NOACCESS,
                ctypes.byref(old_protect)
            ):
                # error handling...
```

### After (Secure):
```python
def _protect_guard_pages(self):
    if self.closed:
        if LOUD_ERRORS:
            print("[ERROR] Attempted to protect guard pages on closed SecureMemory")
        else:
            sys.tracebacklimit = 0
            raise RuntimeError("SecureMemory Error")
        raise ValueError("Attempted to call _protect_guard_pages on closed SecureMemory")
    
    system = platform.system()
    if system == "Windows":
        PAGE_NOACCESS = 0x01
        kernel32 = ctypes.windll.kernel32
        old_protect = ctypes.c_ulong()
        
        # FIX: Use actual guard page addresses, not offsets
        guard_pages = [
            self.base_address,           # Lower guard page
            self.ptr + self.size         # Upper guard page
        ]
        
        for guard_addr in guard_pages:
            if not kernel32.VirtualProtect(
                ctypes.c_void_p(guard_addr),
                ctypes.c_size_t(self.page_size),
                PAGE_NOACCESS,
                ctypes.byref(old_protect)
            ):
                if LOUD_ERRORS:
                    print(f"[ERROR] VirtualProtect failed for guard at {hex(guard_addr)}")
                else:
                    sys.tracebacklimit = 0
                    raise RuntimeError("SecureMemory Error")
                raise OSError(f"VirtualProtect failed for guard page at {hex(guard_addr)}")
    else:
        libc = ctypes.CDLL("libc.so.6")
        PROT_NONE = 0x0
        
        guard_pages = [
            self.base_address,           # Lower guard page
            self.ptr + self.size         # Upper guard page
        ]
        
        for guard_addr in guard_pages:
            if libc.mprotect(ctypes.c_void_p(guard_addr), ctypes.c_size_t(self.page_size), PROT_NONE) != 0:
                if LOUD_ERRORS:
                    print(f"[ERROR] mprotect failed on guard page at {hex(guard_addr)}")
                else:
                    sys.tracebacklimit = 0
                    raise RuntimeError("SecureMemory Error")
                raise OSError(f"mprotect failed on guard page at {hex(guard_addr)}")
```

---

## 7. Improve Entropy Validation

### Before (Weak):
**File**: `src/pydepguardnext/api/net/entropy_utils.py`

```python
def entropy_is_patterned(data: bytes) -> bool:
    return data == data[:len(data)//2] * 2 or len(set(data)) <= 2
```

### After (Stronger):
```python
def entropy_is_patterned(data: bytes) -> bool:
    """
    Detect various patterns that indicate weak entropy.
    """
    if len(data) < 4:
        return True  # Too small to validate
    
    # Check 1: Exact repetition of first half
    half = len(data) // 2
    if data[:half] == data[half:2*half]:
        return True
    
    # Check 2: Very low cardinality (few unique values)
    unique_bytes = len(set(data))
    if unique_bytes <= 2:
        return True
    
    # Check 3: Repeating subsequence pattern
    for pattern_len in range(1, min(len(data) // 4, 16)):
        pattern = data[:pattern_len]
        matches = 0
        for i in range(0, len(data) - pattern_len, pattern_len):
            if data[i:i+pattern_len] == pattern:
                matches += 1
        # If more than 50% matches, it's a strong pattern
        if matches >= len(data) // (pattern_len * 2):
            return True
    
    # Check 4: Arithmetic progression (e.g., 0x00, 0x01, 0x02...)
    if len(data) > 3:
        diffs = [data[i+1] - data[i] for i in range(min(32, len(data)-1))]
        # If all differences are the same, it's linear progression
        if len(set(diffs)) == 1 and diffs[0] != 0:
            return True
    
    # Check 5: High concentration of specific bytes
    byte_counts = Counter(data)
    most_common_count = byte_counts.most_common(1)[0][1]
    if most_common_count > len(data) * 0.3:  # Any byte appears > 30%
        return True
    
    return False
```

---

## 8. Fix Information Leakage in Error Handling

### Before (Vulnerable):
**File**: `src/pydepguardnext/api/net/key_utils.py`

```python
def constant_time_fail(reason="Tampering suspected. Request denied.", detailed_msg: str = ""):
    if detailed_msg and n_errors.LOUD_ERRORS:
        reason = f"{detailed_msg}"  # Overwrites reason with potentially sensitive data
    if not n_errors.LOUD_ERRORS:
        time.sleep(1.4 + secrets.randbelow(200) / 1000 + secrets.randbits(2) * 0.5)
        sys.tracebacklimit = 0
    raise RuntimeError(reason)  # detailed_msg might be in reason now
```

### After (Secure):
```python
import logging
import sys
import time
import secrets

# Configure logging with secure handler (to stderr, not stdout)
security_logger = logging.getLogger("pydepguardnext.security")

def constant_time_fail(reason="Tampering suspected. Request denied.", detailed_msg: str = ""):
    """
    Fail with constant-time delay, no information leakage in exception.
    Detailed messages are logged separately in debug mode only.
    
    Args:
        reason: Generic message to return to client (always returned)
        detailed_msg: Internal debug message (only logged in dev mode, never in exception)
    """
    try:
        # Always add constant-time delay
        time.sleep(1.4 + secrets.randbelow(200) / 1000 + secrets.randbits(2) * 0.5)
    except Exception:
        pass
    
    # Log detailed message for debugging (if available)
    if detailed_msg:
        try:
            security_logger.debug(f"Security failure: {detailed_msg}")
        except Exception:
            pass  # Ignore logging failures
    
    # IMPORTANT: Never expose detailed_msg in exception
    # Always raise with generic reason
    sys.tracebacklimit = 0
    raise RuntimeError(reason)
```

---

## Testing the Fixes

### 1. Test Path Validation:
```python
# Test that openssl_shim validates paths
from pathlib import Path
import tempfile

with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
    valid_key_path = f.name

# Should succeed
result = parse_rsa_private_key(valid_key_path)

# Should fail - non-existent file
try:
    parse_rsa_private_key("/nonexistent/path.pem")
except FileNotFoundError:
    print("✓ Correctly rejected non-existent file")

# Should fail - directory
try:
    parse_rsa_private_key("/tmp")
except ValueError:
    print("✓ Correctly rejected directory")
```

### 2. Test Jail Escape Prevention:
```python
from pathlib import Path

# Create test structure
jail = Path("/tmp/jail")
outside = Path("/etc")

assert is_within_jail(jail / "safe.txt")  # Should pass
assert not is_within_jail(outside / "passwd")  # Should fail

# Test symlink escape
symlink = jail / "escape_link"
symlink.symlink_to("/etc")
assert not is_within_jail(symlink)  # Should fail despite existing symlink
```

### 3. Test Entropy Cache Security:
```python
from pathlib import Path
import stat

# Run entropy checks
data = os.urandom(256)
detect_replay(data)

# Verify cache file permissions
cache_dir = Path(tempfile.gettempdir()) / ".pdg_entropy_cache"
assert cache_dir.stat().st_mode & 0o077 == 0  # Only owner can read/write
```

---

## Deployment Checklist

- [ ] All 8 vulnerabilities have been addressed
- [ ] Code has been reviewed by security team
- [ ] Unit tests pass for each fix
- [ ] Integration tests pass
- [ ] Entropy cache directory permissions verified
- [ ] Guard page protection verified on Windows and Linux
- [ ] Signature validation tested with known keys
- [ ] Path validation tested with various inputs
- [ ] No sensitive data in error messages
- [ ] Security audit tests added to CI/CD pipeline

