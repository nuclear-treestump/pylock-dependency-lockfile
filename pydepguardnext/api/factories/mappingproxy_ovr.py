"""
Hardened MappingProxyType replacement to prevent unauthorized access to sensitive keys.
NOT IN USE YET - UNDER DEVELOPMENT. Part of the factories folder to override builtins.
But yeah, this is a thing now.

Looks like MappingProxyType, talks like MappingProxyType, responds to isinstance() like MappingProxyType...
...but is not MappingProxyType. Muahahaha.
"""

import inspect
from uuid import uuid4
from collections.abc import Mapping
from pydepguardnext.api.log.logit import logit

logslug = "api.factories.mappingproxy_ovr"

VAULT = {}
VAULT_ID = int()
VAULT_KEY = ""

try:
    from pydepguardnext import _MANIFEST
except ImportError:
    _MANIFEST = {}
    logit("Warning: _MANIFEST not found, defaulting to empty manifest.", "w", source=f"{logslug}.inline")

print("MANIFEST:", _MANIFEST)

# Save the original MappingProxyType
import types as _types

_ORIGINAL_MPT = _types.MappingProxyType

# Define keys that should not be exposed unless internal

_PROTECTED_KEYS = {"secrets":[]}

def _is_hardened():
    return _MANIFEST.get("locks", {}).get("hardened", False)

def _caller_is_safe():
    """Only pydepguardnext modules and __main__ bypass ZebraProxy enforcement."""
    stack = inspect.stack()
    for frame in stack:
        mod = inspect.getmodule(frame[0])
        if not mod:
            print("[MPT BYPASS] No module found in stack frame, skipping")
            continue
        if mod.__name__.startswith("pydepguardnext.") or mod.__name__ == "__main__":
            print(f"[MPT BYPASS] Access granted to {mod.__name__}")
            return True
    return False

from abc import ABCMeta

class ZebraMeta(ABCMeta):
    """Metaclass to spoof isinstance checks for MappingProxyType."""
    def __instancecheck__(cls, instance):
        if isinstance(instance, ZebraProxy):
            return True
        return super().__instancecheck__(instance)

    
    

class ZebraProxy(Mapping, metaclass=ZebraMeta):
    """A hardened MappingProxyType replacement that restricts access to protected keys."""
    # Now I have MPT control, even the socalled "immutable" MappingProxyType can be made mutable
    __slots__ = ("_data", "_protected")

    def __init__(self, data):
        self._data = dict(data)
        self._protected = _PROTECTED_KEYS["secrets"]
        if VAULT_KEY in self._data:

    @property
    def __class__(self):
        if not _caller_is_safe():
            return _ORIGINAL_MPT
        return type(self)
    
    @__class__.setter
    def __class__(self, value):
        if not _is_hardened():
            object.__setattr__(self, "__class__", value)
        else: 
            from pydepguardnext import PyDepBullshitDetectionError
            raise PyDepBullshitDetectionError(msg="Reassignment of __class__ is forbidden in hardened context.")

    def __getattribute__(self, name):
        if name == "__class__" and not _caller_is_safe():
            return _ORIGINAL_MPT
        return object.__getattribute__(self, name)

    def __getitem__(self, key):
        auth = False
        stack = inspect.stack()
        caller = None
        for frame in stack:
            mod = inspect.getmodule(frame[0])
            if mod:
                caller = mod.__name__
                break
        if caller is None:
            caller = "<unknown>"
        if id(self) == VAULT_ID:
            # This is the official VAULT object
            if _is_hardened() and not _caller_is_safe():
                from pydepguardnext import PyDepBullshitDetectionError
                raise PyDepBullshitDetectionError(
                    msg=f"TypeError: Unauthorized access to guarded VAULT contents via __getitem__ by {caller}"
                )
        if key in self._protected:
            print(f"[MPT PROTECTED] Attempt to access protected key: {key} via __getitem__ after id check")
            """Only pydepguardnext modules and __main__ bypass ZebraProxy enforcement."""
            stack = inspect.stack()
            for frame in stack:
                mod = inspect.getmodule(frame[0])
                print("FRAME: ", frame)
                print("MODULE: ", mod)
                if not mod:
                    print("[MPT BYPASS] No module found in stack frame, skipping")
                    continue
                if mod.__name__.startswith("pydepguardnext.") or mod.__name__ == "__main__":
                    print(f"[MPT BYPASS] Access granted to {mod.__name__}")
                    auth = True
                    break
            if _is_hardened() and not auth:
                from pydepguardnext import PyDepBullshitDetectionError
                raise PyDepBullshitDetectionError(
                    msg=f"TypeError: Unsafe access to protected key: {key}"
                )
            raise RuntimeError(f"[MPT BLOCKED] Unsafe access to: {key}")
        return self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)

    def __contains__(self, key):
        return key in self._data

    def keys(self):
        return self._data.keys()

    def values(self):
        return self._data.values()

    def items(self):
        return self._data.items()

    def __repr__(self):
        try:
            safe = {k: v if k not in self._protected else "***" for k, v in self._data.items()}
            return f"mappingproxy({repr(safe)})"
        except Exception:
            return "mappingproxy(<redacted>)"
    def __getattr__(self, attr):
        # Prevent monkeypatching attempt via __dict__ or unknown reflection
        if attr == "__dict__" and _is_hardened():
            from pydepguardnext import PyDepBullshitDetectionError
            raise PyDepBullshitDetectionError(msg="Attempted access to __dict__ on ZebraProxy") 
        raise AttributeError(f"{type(self).__name__} object has no attribute {attr!r}")

    def __class_getitem__(cls, item):
        return cls  # for compatibility
    
    def keys(self):
        if id(self) == VAULT_ID and _is_hardened() and not _caller_is_safe():
            from pydepguardnext import PyDepBullshitDetectionError
            raise PyDepBullshitDetectionError(
                msg="TypeError: Unauthorized access to guarded VAULT contents via keys()"
            )
        return self._data.keys()

    # --- PDGN internal-only hooks ---
    def _set(self, k, v):
        self._data[k] = v

    def _del(self, k):
        self._data.pop(k, None)

    def _raw_dict(self):
        return self._data.copy()
    
class GuardedMappingProxyType(type):
    def __instancecheck__(self, instance):
        return isinstance(instance, ZebraProxy)

# Guard replacement factory
class GuardedMappingProxyFactory(metaclass=GuardedMappingProxyType):
    def __new__(cls, obj, *args, **kwargs):
        return ZebraProxy(obj, *args, **kwargs)

("[MPT GUARD] Hardened MappingProxyType injected")
import types
types.MappingProxyType = GuardedMappingProxyFactory

# TODO: THIS IS DEBUG OUTPUT, REMOVE LATER
print("TYPE: ", type(_types.MappingProxyType))
print("TYPE: ", type(types.MappingProxyType))
print("TYPE: ", type(_ORIGINAL_MPT))
print("TYPE: ", type(ZebraProxy))
print("TYPE: ", type(GuardedMappingProxyFactory))
print("TYPE: ", type(GuardedMappingProxyType))
print("TYPE: ", type(ZebraMeta))

print("TYPE: ", types.MappingProxyType)

# Manual override restore
def restore_mpt():
    print("ORIGINAL TYPE: ", types.MappingProxyType)
    print("RESTORING TYPE: ", _ORIGINAL_MPT)
    print("_MANIFEST: ", _MANIFEST)
    print("Protected keys:", _PROTECTED_KEYS)
    print("SALT: ", VAULT.get("secret_key"))

    types.MappingProxyType = _ORIGINAL_MPT
    print("[MPT GUARD] Restored MappingProxyType")





def build_protected_keys():
    global _PROTECTED_KEYS
    print("[MPT PROTECTED] Building protected keys list...")
    global VAULT, VAULT_ID, VAULT_KEY
    if VAULT_KEY in VAULT:
        print("SALT: ", VAULT[VAULT_KEY])
        print("VAULT_ID: ", VAULT_ID)
        print("VAULT_KEY: ", VAULT_KEY)
        _PROTECTED_KEYS["secrets"] = [VAULT_KEY]
    else:
        print("[MPT PROTECTED] No vault key found, no protected keys set.")
    global _VAULT_ID
    _VAULT_ID = _ORIGINAL_MPT({"vid": VAULT_ID})

from pydepguardnext import _set_vault
_set_vault()
build_protected_keys()