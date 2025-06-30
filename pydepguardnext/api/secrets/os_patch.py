import os
from pydepguardnext.api.secrets.secretentry import PyDepSecMap
from pydepguardnext.api.log.logit import logit
import sys
from collections.abc import MutableMapping

logslug = "api.secrets.os_patch"

class SecureEnviron(MutableMapping):
    """
    A secure, secrets-aware replacement for `os.environ`.

    SecureEnviron enforces access policies on runtime secrets managed by `PyDepSecMap`,
    transparently simulating environment variable injection with support for:
    - TTL (time-to-live)
    - One-time reads or capped read counts
    - Remapped environment variable names via `mock_env_name`
    - Redaction after expiration or disallowed access

    Compatible with all common dictionary methods including `__getitem__`, `__contains__`,
    and iteration (`for key in environ:`). Designed for sandboxed scripts that require
    controlled access to sensitive data without leaking real `os.environ` state.

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

    logit("os.environ and getenv patched with SecureEnviron", "i", source=f"{logslug}.{__name__}")

def auto_patch_from_secrets(secmap: PyDepSecMap):
    if any(s.mock_env for s in secmap._secrets.values()):
        patch_environ_with_secmap(secmap)
