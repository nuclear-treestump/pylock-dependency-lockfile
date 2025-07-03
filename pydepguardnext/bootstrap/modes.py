# pydepguardnext/bootstrap/modes.py

from enum import Enum, auto
from dataclasses import dataclass

class BootMode(Enum):
    # Boot Modes
    SECURE = auto()
    STANDALONE = auto()
    CHILD = auto()
    LIGHT = auto()
    DEBUG = auto()
    UNDEFINED = auto()

@dataclass(frozen=True)
class RuntimeConfig:
    mode: BootMode
    hardened: bool
    parent_uuid: str | None
    no_capture: bool
    flags: dict

RUNTIME_MODE: RuntimeConfig = RuntimeConfig(
    mode=BootMode.UNDEFINED,
    hardened=False,
    parent_uuid=None,
    no_capture=False,
    flags={}
)
