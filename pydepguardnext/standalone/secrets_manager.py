import os
os.environ["PYDEP_STANDALONE_NOSEC"] = "1"
import sys
from collections.abc import MutableMapping
import json
import time
from typing import Optional, Dict, Any
import threading
from dataclasses import dataclass, field
from pydepguardnext import __child, __skip_secure_boot

if not __child and __skip_secure_boot:
    os.environ["PYDEP_STANDALONE_NOSEC"] = "1"

def log_event(event_type: str, payload: dict):
    print(json.dumps({
        "event": event_type,
        "timestamp": time.time(),
        "payload": payload
    }))

@dataclass
class SecretEntry:
    value: str
    access_id: Optional[str] = None
    ttl_seconds: Optional[int] = None
    read_once: bool = False
    read_max: Optional[int] = None
    mock_env: bool = False
    mock_env_name: Optional[str] = None

    created_at: float = field(default_factory=time.time)
    reads: int = 0
    expired: bool = False
    def __init__(
        self,
        value: str,
        access_id: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
        read_once: bool = False,
        read_max: Optional[int] = None,
        mock_env: bool = False,
        mock_env_name: Optional[str] = None
    ):
        self._value = value
        self.access_id = access_id
        self.ttl = ttl_seconds
        self.read_once = read_once
        self.read_max = read_max
        self.mock_env = mock_env
        self.mock_env_name = mock_env_name or ""
        self.created_at = time.time()
        self.reads = 0
        self.expired = False

    def is_expired(self) -> bool:
        if self.expired:
            return True
        if self.ttl is not None and (time.time() - self.created_at) > self.ttl:
            self.expired = True
        if self.read_max is not None and self.reads >= self.read_max:
            self.expired = True
        return self.expired

    def get(self) -> Optional[str]:
        if self.is_expired():
            return None
        self.reads += 1
        if self.read_once or (self.read_max and self.reads >= self.read_max):
            self.expired = True
        return self._value

    def redact(self):
        self._value = "***"
        self.expired = True

    def serialize(self) -> Dict[str, Any]:
        return {
            "access_id": self.access_id,
            "ttl": self.ttl,
            "read_once": self.read_once,
            "read_max": self.read_max,
            "reads": self.reads,
            "expired": self.expired,
            "mock_env": self.mock_env,
            "mock_env_name": self.mock_env_name,
            "value": "***" if self.expired else "<present>"
        }

class PyDepSecMap:
    def __init__(self):
        self._secrets: Dict[str, SecretEntry] = {}

    def add(self, name: str, entry: SecretEntry):
        if not isinstance(name, str):
            raise TypeError(f"Secret key must be a string, got {type(name).__name__}")
        self._secrets[name] = entry

    def get(self, name: str) -> Optional[str]:
        entry = self._secrets.get(name)
        if not entry:
            return None
        value = entry.get()
        if entry.access_id:
            log_event("secret_access", {"key": name, "access_id": entry.access_id})
        if entry.is_expired():
            log_event("secret_expiry", {"key": name})
        return value

    def __getitem__(self, name: str):
        return self.get(name)

    def redact_expired(self):
        for name, entry in self._secrets.items():
            if entry.is_expired():
                entry.redact()

    def to_env(self) -> Dict[str, str]:
        return {
            entry.mock_env_name or name: entry.get()
            for name, entry in self._secrets.items()
            if entry.mock_env and not entry.is_expired()
        }

    def serialize(self):
        return {k: v.serialize() for k, v in self._secrets.items()}

def start_secret_watchdog(secmap: PyDepSecMap, interval=5):
    def watchdog():
        while True:
            time.sleep(interval)
            secmap.redact_expired()
    thread = threading.Thread(target=watchdog, daemon=True)
    thread.start()

class SecureEnviron(MutableMapping):
    """
    A secure, secrets-aware replacement for os.environ.

    SecureEnviron enforces access policies on runtime secrets managed by PyDepSecMap,
    transparently simulating environment variable injection with support for:
    - TTL (time-to-live)
    - One-time reads or capped read counts
    - Remapped environment variable names via mock_env_name
    - Redaction after expiration or disallowed access

    Compatible with all common dictionary methods including __getitem__, __contains__,
    and iteration (for key in environ:). Designed for sandboxed scripts that require
    controlled access to sensitive data without leaking real os.environ state.

    Parameters
    ----------
    secmap : PyDepSecMap
        The secret mapping used to populate secure environment values.
    """
    def __init__(self, secmap):
        """
        Initialize a SecureEnviron.

        Parameters
        ----------
        secmap : PyDepSecMap
            A mapping of secret keys to SecretEntry objects.
        """
        self._base = dict(os.environ)
        self._secrets = secmap

    def __getitem__(self, key):
        """
        Retrieve the value for a given environment variable.

        Returns secret values if present and authorized; otherwise falls back to base environment.

        Raises
        ------
        KeyError
            If the key is not found or access is denied due to expiration.
        """
        for name, entry in self._secrets._secrets.items():
            if not entry.mock_env or entry.is_expired():
                continue
            effective_key = entry.mock_env_name or name
            if effective_key == key:
                value = entry.get()
                if value is None:
                    raise KeyError(key)
                return value
        if key in self._base:
            return self._base[key]
        raise KeyError(key)

    def __setitem__(self, key, value):
        """
        Set a key in the base environment.

        Note: This does not modify secrets.
        """
        self._base[key] = value

    def __delitem__(self, key):
        """
        Delete a key from the base environment.

        Raises
        ------
        KeyError
            If the key is not found in the base environment.
        """
        if key in self:
            for name, entry in self._secrets._secrets.items():
                effective_key = entry.mock_env_name or name
                if effective_key == key and not entry.is_expired():
                    raise TypeError(f"Cannot delete secure secret-bound key: {key}")
        if key in self._base:
            del self._base[key]
        else:
            raise KeyError(key)

    def __iter__(self):
        """
        Iterate over all visible environment keys.

        Includes both base environment and authorized secrets using mock_env_name if provided.
        """
        seen = set()
        for key in self._base:
            yield key
            seen.add(key)
        for name, entry in self._secrets._secrets.items():
            if entry.mock_env and not entry.is_expired():
                effective_key = entry.mock_env_name or name
                if effective_key not in seen:
                    yield effective_key
                    seen.add(effective_key)

    def __len__(self):
        """Return the total number of exposed keys."""
        return len(list(iter(self)))

    def get(self, key, default=None):
        """
        Retrieve a value with a fallback default.

        Parameters
        ----------
        key : str
            The environment key to retrieve.
        default : Any
            A default value to return if the key is not found.

        Returns
        -------
        str or Any
            The value from secrets or base, or the default if not found.
        """
        try:
            return self.__getitem__(key)
        except KeyError:
            return default

    def __contains__(self, key):
        """
        Check if a key exists in the secure environment.

        Returns
        -------
        bool
            True if the key is present and readable; False otherwise.
        """
        if key in self._base:
            return True
        for name, entry in self._secrets._secrets.items():
            if not entry.mock_env or entry.is_expired():
                continue
            effective_key = entry.mock_env_name or name
            if effective_key == key:
                return True
        return False

    def redact(self):
        """
        Redact all currently active secrets.

        This forcibly clears all accessible mock_env secrets
        from the internal mapping. After this, secret keys will
        raise KeyError or return None depending on access method.
        """
        for name, entry in self._secrets._secrets.items():
            if entry.mock_env and not entry.is_expired():
                entry.redact()

    def __repr__(self):
        """
        Return a redacted preview of visible secure environment state.

        Includes:
        - All base environment keys (with values hidden)
        - All active mock_env secrets (with names only, values hidden or marked)
        """
        keys = list(self._base.keys())
        secret_keys = []
        for name, entry in self._secrets._secrets.items():
            if entry.mock_env and not entry.is_expired():
                key_name = entry.mock_env_name or name
                secret_keys.append(f"{key_name}=<secret>")

        return (
            f"<SecureEnviron "
            f"(base_keys={len(keys)}, secrets={len(secret_keys)}): "
            f"{', '.join(secret_keys)}>"
        )
    
    

def patch_environ_with_secmap(secmap: PyDepSecMap):
    secure_env = SecureEnviron(secmap)
    os.environ = secure_env
    os.getenv = secure_env.get  # Not a lambda

    # Also patch the module-level binding to trap 'from os import environ'
    sys.modules["os"].environ = os.environ
    sys.modules["os"].getenv = os.getenv

    log_event("secure_environ_patched", {
        "timestamp": time.time(),
        "source": f"{__name__}",
        "secrets_count": len(secmap._secrets)
    })

def auto_patch_from_secrets(secmap: PyDepSecMap):
    if any(s.mock_env for s in secmap._secrets.values()):
        patch_environ_with_secmap(secmap)

from typing import NamedTuple
class SecretsHandle(NamedTuple):
    secmap: PyDepSecMap
    to_env: Dict[str, str]

def use_secrets(secrets: Dict[str, SecretEntry], auto_patch=True) -> SecretsHandle:
    """
    Creates a PyDepSecMap from a dictionary of secrets and optionally patches os.environ.

    Parameters
    ----------
    secrets : dict[str, SecretEntry]
        A dictionary mapping keys to SecretEntry objects.
    auto_patch : bool
        Whether to automatically patch os.environ with SecureEnviron.

    Note
    ----
    If subprocesses are spawned, use `secmap.to_env()` and pass it explicitly
    to avoid secret leakage, since SecureEnviron is not inherited across processes.

    Returns
    -------
    PyDepSecMap
    """
    secmap = PyDepSecMap()
    for k, v in secrets.items():
        secmap.add(k, v)

    if auto_patch:
        auto_patch_from_secrets(secmap)

    return SecretsHandle(secmap=secmap, to_env=secmap.to_env())


__all__ = [
    "SecretEntry",
    "PyDepSecMap",
    "SecureEnviron",
    "use_secrets",
    "patch_environ_with_secmap",
    "auto_patch_from_secrets",
    "start_secret_watchdog"
]