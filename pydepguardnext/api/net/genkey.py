from types import MappingProxyType
from .key_utils import shred_locals_by_ref, constant_time_fail
from .entropy_utils import random_checks
from .memoryhandler import SecureMemory

SADISM_LEVEL = MappingProxyType({
    "low": 2048,
    "medium": 4096,
    "high": 8192,
})