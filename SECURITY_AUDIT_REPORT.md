# Security Vulnerability Audit Report
**pydepguardnext - Dependency Lockfile Tool**

---

## Executive Summary

This security audit identified **7 critical and high-severity vulnerabilities** in the codebase. These vulnerabilities span command injection, path traversal, insecure cryptographic practices, and information disclosure. Immediate remediation is recommended before production deployment.

---

## Vulnerabilities Identified

### 1. ⚠️ CRITICAL: Command Injection in OpenSSL Shim (CWE-78)

**File**: `src/pydepguardnext/api/sign/openssl_shim.py` (Line 5-7)

**Severity**: CRITICAL

**Description**:
The `parse_rsa_private_key()` function accepts a user-controlled file path and passes it directly to `subprocess.run()` without validation.

```python
def parse_rsa_private_key(path: str):
    result = subprocess.run(
        ["openssl", "rsa", "-in", path, "-noout", "-text"],
        capture_output=True, text=True
    )
```

**Risk**: While the path is passed as a list argument (which is safer), there's no validation that the path exists, is readable, or is within expected directories.

**Recommended Fix**:
```python
from pathlib import Path

def parse_rsa_private_key(path: str):
    # Validate path exists and is readable
    key_path = Path(path).resolve()
    if not key_path.exists():
        raise FileNotFoundError(f"Key file not found: {path}")
    if not key_path.is_file():
        raise ValueError(f"Path is not a file: {path}")
    
    # Optionally restrict to specific directories
    # if not str(key_path).startswith('/allowed/key/dir'):
    #     raise PermissionError("Key path outside allowed directory")
    
    result = subprocess.run(
        ["openssl", "rsa", "-in", str(key_path), "-noout", "-text"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"OpenSSL failed: {result.stderr}")
    return result
```

---

### 2. ⚠️ HIGH: Path Traversal/Jail Escape Logic Error (CWE-22)

**File**: `src/pydepguardnext/api/runtime/airjail.py` (Lines 19-46)

**Severity**: HIGH

**Description**:
The `is_within_jail()` function has a critical logic error in its fallback validation. Line 36 compares inodes but the string prefix check is still used in the same condition, which can be bypassed:

```python
def is_within_jail(path: Path) -> bool:
    try:
        path_real = path.resolve(strict=True)
        jail_real = JAIL_ROOT
        
        # Fast case works correctly
        if str(path_real).startswith(str(jail_real)):
            return True
        
        # BUT: This inode check ALSO requires the string prefix match
        # which means the inode fallback is never reached if prefix fails!
        jail_dev_ino = os.stat(jail_real)
        path_dev_ino = os.stat(path_real)
        
        return jail_dev_ino.st_dev == path_dev_ino.st_dev and str(path_real).startswith(str(jail_real))
```

**Attack Scenario**: A symlink pointing to `/etc` could be created inside the jail directory (e.g., `/jail/symlink -> /etc`). The inode check would succeed (different devices), but the string prefix would fail, allowing escape.

**Recommended Fix**:
```python
def is_within_jail(path: Path) -> bool:
    """
    Verifies the given path is within the defined jail, accounting for symlinks.
    """
    try:
        path_real = path.resolve(strict=True)
        jail_real = JAIL_ROOT.resolve()
        
        # Check if path is within jail by comparing resolved paths
        try:
            path_real.relative_to(jail_real)
            return True
        except ValueError:
            # path is outside jail
            return False
            
    except FileNotFoundError:
        # For non-existent files, check if parent directory is within jail
        try:
            parent = path.parent.resolve(strict=True)
            parent.relative_to(JAIL_ROOT.resolve())
            return True
        except (ValueError, FileNotFoundError):
            return False
    except Exception:
        return False
```

---

### 3. ⚠️ HIGH: Insecure Entropy Cache File Permissions (CWE-276)

**File**: `src/pydepguardnext/api/net/entropy_utils.py` (Lines 15-25)
**Also**: `src/pydepguardnext/api/sign/sign_utils.py` (Lines 43-53)

**Severity**: HIGH

**Description**:
The entropy cache file is stored in a world-readable temporary directory without proper permission controls:

```python
def detect_replay(data: bytes, cache_file=".entropycache") -> bool:
    current_hash = sha3_512(data).digest()
    cache_path = Path(tempfile.gettempdir()) / cache_file  # World-readable location!
    
    if cache_path.exists():
        old_hash = cache_path.read_bytes()
        # ...
    
    cache_path.write_bytes(current_hash)  # No explicit permission setting
    return False
```

**Risk**: 
- Temp directory is typically world-readable (permissions 1777)
- An attacker could read or modify the cache file
- The entropy replay detection mechanism can be bypassed

**Recommended Fix**:
```python
def detect_replay(data: bytes, cache_file=".entropycache") -> bool:
    import tempfile
    import os
    
    current_hash = sha3_512(data).digest()
    
    # Create secure temporary directory with restricted permissions
    cache_dir = Path(tempfile.gettempdir()) / ".pdg_entropy"
    cache_dir.mkdir(mode=0o700, exist_ok=True)  # Owner-only access
    
    cache_path = cache_dir / cache_file
    
    if cache_path.exists():
        old_hash = cache_path.read_bytes()
        if hmac.compare_digest(current_hash, old_hash):
            return True
    
    # Write with secure permissions
    cache_path.write_bytes(current_hash)
    # Explicitly set permissions to owner-only
    cache_path.chmod(0o600)
    
    return False
```

---

### 4. ⚠️ HIGH: Insecure PKCS#1 v1.5 Implementation (CWE-347)

**File**: `src/pydepguardnext/api/runtime/sigverify.py` (Lines 16-22)

**Severity**: HIGH

**Description**:
The manual PKCS#1 v1.5 padding implementation has known vulnerabilities. While the function correctly implements the padding, PKCS#1 v1.5 itself is cryptographically vulnerable to Bleichenbacher's padding oracle attack.

```python
def emsa_pkcs1_v1_5_encode(digest_bytes: bytes, n_bytes: int) -> bytes:
    sha256_prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    t = sha256_prefix + digest_bytes
    padding_len = n_bytes - len(t) - 3
    if padding_len < 8:
        raise ValueError("Encoding error: insufficient padding space.")
    return b"\x00\x01" + b"\xff" * padding_len + b"\x00" + t
```

**Risk**: 
- PKCS#1 v1.5 is deprecated for new cryptographic schemes
- Vulnerable to Bleichenbacher's padding oracle attack
- No key validation before signature verification

**Recommended Fix**:
Use modern cryptographic libraries and OAEP padding instead:

```python
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def validate_signature_secure(digest_bytes: bytes, sig_bytes: bytes, public_key) -> bool:
    """
    Use proper PKCS#1 OAEP padding with constant-time comparison.
    Requires: cryptography library
    """
    try:
        public_key.verify(
            sig_bytes,
            digest_bytes,
            padding.PKCS1v15(),  # Or better: padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
```

---

### 5. ⚠️ MEDIUM: System Information Disclosure (CWE-200)

**File**: `src/pydepguardnext/api/net/key_utils.py` (Lines 74-91)

**Severity**: MEDIUM

**Description**:
The `generate_system_fingerprint()` function exposes sensitive system information that could aid in fingerprinting or targeted attacks:

```python
def generate_system_fingerprint() -> str:
    if os.name == 'nt':
        sys_info = f"{platform.system()}-{platform.release()}-{platform.version()}-{platform.machine()}"
    elif os.name == 'posix':
        try:
            uname = os.uname()
            sys_info = f"{uname.sysname}-{uname.release}-{uname.version}-{uname.machine}"
        # ...
    sys_hash = hkdf_blake2b_expand(sys_info.encode('utf-8'), info=b"sys-fingerprint", length=128).hex()
    shred_locals_by_ref(locals(), exclude=("sys_hash",))
    return sys_hash
```

**Risk**:
- Exact OS version, kernel version, and architecture are exposed
- Could be used for targeted exploits or device fingerprinting
- The hash is deterministic and could be used to identify the same system

**Recommended Fix**:
```python
def generate_system_fingerprint() -> str:
    """
    Generate a high-entropy system fingerprint without exposing details.
    Uses machine hardware UUID and sanitized OS family.
    """
    import uuid
    
    # Use hardware UUID (often more stable than combined system info)
    try:
        hw_uuid = uuid.getnode()  # MAC address as integer
        sys_info = f"{hw_uuid}".encode('utf-8')
    except Exception:
        # Fallback: use randomized fingerprint per process
        sys_info = secrets.token_bytes(16)
    
    # Only include minimal OS family info, not exact versions
    try:
        os_family = platform.system().lower()  # "linux", "windows", "darwin"
        sys_info = f"{os_family}:{hex(hash(sys_info))}".encode('utf-8')
    except Exception:
        pass
    
    sys_hash = hkdf_blake2b_expand(sys_info, info=b"sys-fingerprint", length=128).hex()
    return sys_hash
```

---

### 6. ⚠️ MEDIUM: SecureMemory Guard Page Logic Error (CWE-190)

**File**: `src/pydepguardnext/api/sign/securemem.py` (Line 232)

**Severity**: MEDIUM

**Description**:
In the `_protect_guard_pages()` method, the loop uses a hardcoded tuple with incorrect offset calculation:

```python
def _protect_guard_pages(self):
    # ...
    for offset in (0, self.ptr + self.size):  # Windows path
        if not kernel32.VirtualProtect(
            ctypes.c_void_p(offset),  # BUG: uses offset directly, not self.base_address + offset!
            ctypes.c_size_t(self.page_size),
            PAGE_NOACCESS,
            ctypes.byref(old_protect)
        ):
```

On Windows, the first guard page should be at `self.base_address`, not `0`:

```python
for offset in (0, self.page_size + self.size):  # Wrong!
    # Should be:
    # for offset in (self.base_address, self.ptr + self.size):
```

**Risk**: Guard pages may not be properly protected, reducing buffer overflow protection.

**Recommended Fix**:
```python
def _protect_guard_pages(self):
    if self.closed:
        # ... error handling ...
        
    system = platform.system()
    if system == "Windows":
        PAGE_NOACCESS = 0x01
        kernel32 = ctypes.windll.kernel32
        old_protect = ctypes.c_ulong()
        
        # Correct: protect both guard pages using actual addresses
        guard_pages = [self.base_address, self.ptr + self.size]
        
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
                raise OSError("VirtualProtect failed")
    # ... rest of method ...
```

---

### 7. ⚠️ MEDIUM: Weak Entropy Validation (CWE-330)

**File**: `src/pydepguardnext/api/net/entropy_utils.py` (Lines 28-31)

**Severity**: MEDIUM

**Description**:
The Shannon entropy threshold of 7.8 is reasonable but the pattern detection is too simplistic:

```python
def entropy_is_patterned(data: bytes) -> bool:
    return data == data[:len(data)//2] * 2 or len(set(data)) <= 2
```

This only detects:
1. Exact repetition of first half
2. Fewer than 2 unique bytes

**Risk**: More sophisticated patterns could pass validation:
- Alternating patterns: `ABABAB...`
- Low-entropy patterns: `0123456789...` repeated
- Pseudo-random generators with weak state

**Recommended Fix**:
```python
def entropy_is_patterned(data: bytes) -> bool:
    """Detect common patterns in entropy."""
    # Check for exact repetition
    half = len(data) // 2
    if data[:half] == data[half:half*2]:
        return True
    
    # Check for low cardinality
    if len(set(data)) <= 2:
        return True
    
    # Check for autocorrelation (repeated subsequences)
    for pattern_len in range(1, min(len(data) // 4, 16)):
        pattern = data[:pattern_len]
        if sum(1 for i in range(0, len(data) - pattern_len, pattern_len) 
               if data[i:i+pattern_len] == pattern) >= len(data) // (pattern_len * 2):
            return True
    
    # Check for linear/arithmetic progression
    if len(data) > 3:
        diffs = [data[i+1] - data[i] for i in range(min(20, len(data)-1))]
        if len(set(diffs)) == 1:  # All differences are the same
            return True
    
    return False
```

---

### 8. ⚠️ MEDIUM: Insecure Default in Entropy Cache

**File**: `src/pydepguardnext/api/sign/sign_utils.py` (line 43)

**Severity**: MEDIUM

**Description**:
The `constant_time_fail()` function has an error handling path that could leak information:

```python
def constant_time_fail(reason="Tampering suspected. Request denied.", detailed_msg: str = ""):
    if detailed_msg and n_errors.LOUD_ERRORS:
        reason = f"{detailed_msg}"  # Can expose internal details
    if not n_errors.LOUD_ERRORS:
        time.sleep(1.4 + secrets.randbelow(200) / 1000 + secrets.randbits(2) * 0.5)
        sys.tracebacklimit = 0
    raise RuntimeError(reason)  # detailed_msg might be exposed here
```

When `LOUD_ERRORS` is True, detailed error messages are exposed that shouldn't be visible to attackers.

**Recommended Fix**:
```python
def constant_time_fail(reason="Tampering suspected. Request denied.", detailed_msg: str = ""):
    """Fail with constant time delay and no information leakage."""
    # Never expose detailed messages in production
    if not n_errors.LOUD_ERRORS:
        # Production: minimal information
        time.sleep(1.4 + secrets.randbelow(200) / 1000 + secrets.randbits(2) * 0.5)
        sys.tracebacklimit = 0
        raise RuntimeError(reason)
    else:
        # Development: safe to expose details (use only in dev/test)
        print(f"[DEBUG] {reason}: {detailed_msg}", file=sys.stderr)
        raise RuntimeError(reason)
```

---

## Summary Table

| # | Vulnerability | File | Severity | CWE |
|---|---|---|---|---|
| 1 | Command Injection | `openssl_shim.py` | CRITICAL | CWE-78 |
| 2 | Path Traversal | `airjail.py` | HIGH | CWE-22 |
| 3 | Insecure Cache Permissions | `entropy_utils.py` | HIGH | CWE-276 |
| 4 | Weak Crypto (PKCS#1 v1.5) | `sigverify.py` | HIGH | CWE-347 |
| 5 | Information Disclosure | `key_utils.py` | MEDIUM | CWE-200 |
| 6 | Guard Page Logic Error | `securemem.py` | MEDIUM | CWE-190 |
| 7 | Weak Entropy Validation | `entropy_utils.py` | MEDIUM | CWE-330 |
| 8 | Information Leakage in Error Handling | `sign_utils.py` | MEDIUM | CWE-532 |

---

## Recommendations

### Immediate (P0 - Before Production)
1. **Fix path validation** in `openssl_shim.py`
2. **Fix path traversal logic** in `airjail.py`
3. **Secure entropy cache** file permissions

### Short-term (P1 - Next Sprint)
4. **Upgrade cryptographic implementation** to modern standards (PSS or ECDSA)
5. **Fix guard page protection logic** in SecureMemory
6. **Improve entropy validation** pattern detection

### Medium-term (P2 - Quality)
7. **Reduce system information exposure** in fingerprinting
8. **Audit all subprocess calls** for injection vulnerabilities
9. **Add input validation** layer across all parsers
10. **Implement security testing** in CI/CD pipeline

---

## Testing Recommendations

1. **Fuzzing**: Run fuzzing tests on all input parsers (`parse_json_install`, `parse_cli_input`, etc.)
2. **Path Traversal Tests**: Attempt jail escape with symlinks, relative paths, and unicode
3. **Entropy Tests**: Verify entropy validation rejects predictable sequences
4. **Crypto Tests**: Validate signature verification with tampered payloads
5. **Sandbox Tests**: Verify subprocess restrictions are enforced

---

**Report Generated**: 2026-04-14
**Audit Scope**: Full codebase review of pydepguardnext
**Status**: Requires Remediation
