from dataclasses import dataclass, field, asdict
from typing import Literal, Union
from datetime import datetime, timezone
import time
import base64
import uuid
from types import MappingProxyType
LOCKED_UUIDS = MappingProxyType({
    "00000000-0000-0000-0000-000000000000": "global_root",
    "11111111-1111-1111-1111-111111111111": "pdgnet-ident",
    "22222222-2222-2222-2222-222222222222": "Reserved for future use",
    "33333333-3333-3333-3333-333333333333": "Reserved for future use",
    "44444444-4444-4444-4444-444444444444": "Reserved for future use",
    "55555555-5555-5555-5555-555555555555": "routing",
    "66666666-6666-6666-6666-666666666666": "Reserved for future use",
    "77777777-7777-7777-7777-777777777777": "Reserved for future use",
    "88888888-8888-8888-8888-888888888888": "Reserved for future use",
    "99999999-9999-9999-9999-999999999999": "pdg-gateway-external",
    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa": "pdgnet-audit",
    "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb": "pdgnet-addressbook",
    "cccccccc-cccc-cccc-cccc-cccccccccccc": "pdgnet-usercode",
    "dddddddd-dddd-dddd-dddd-dddddddddddd": "pdgnet-resolver",
    "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee": "Reserved for future use",
    "ffffffff-ffff-ffff-ffff-ffffffffffff": "Reserved for future use",
})

SYSTEM_TYPES = MappingProxyType({
    "keystore": 0xFFFFFFFF,
    "systemmessage": 0xEEEEEEEE,
    "addressbook": 0xBBBBBBBB,
    "audit": 0xAAAAAAAA,
    "resolver": 0xDDDDDDDD,
    "global": 0x0FFFFFFF,
    "universe": 0x00FFFFFF,
    "dimension": 0x000FFFFF,
    "plane": 0x0000FFFF,
    "parent": 0x00000FFF,
    "child": 0x000000FF,
    "user1stparty": 0x0000000F,
    "blocked": 0x00000000,
})

def default_readable_time() -> str:
    return datetime.now(timezone.utc).isoformat()

def generate_key_uuid() -> str:
    while True:
        candidate = str(uuid.uuid4()).lower()
        if candidate not in LOCKED_UUIDS:
            return candidate

@dataclass
class PDGNetPrivateKey:
    """
    Represents a PDGNet private key with associated metadata.
    """
    
    def get_system_type_value(self) -> int:
        if self.keyscope not in SYSTEM_TYPES:
            raise ValueError(f"Invalid system type: {self.keyscope}")
        return SYSTEM_TYPES[self.keyscope]

    
    # Had to move this above the field definitions so that its accessible to default_factory
    keytype: str = "pdgnet_private"
    keyscope: str = "global"
    keyscope_hex: int = field(init=False)
    keyversion: str = "v1"
    key_uuid: str = field(default_factory=generate_key_uuid)
    encrypted: bool = False
    encryption_algorithm: str = "none"
    encryption_difficulty: str = "none"
    global_gen_time: float = field(default_factory=time.monotonic)
    global_readable_time: str = field(default_factory=default_readable_time)
    global_key_name: str = "pdgnet-global-root"
    global_key_content: str = ""
    expires_on: float = 0.0
    counter: int = 0
    system_fingerprint_hash: str = ""
    global_current_rekey_time: float = 0.0
    compression: Literal["zlib"] = "zlib"
    entropy_difficulty: Union[str, int] = "high"

    

    ttl: int = field(init=False)

    def finalize(self):
        """Call after setting `expires_on` to compute ttl."""
        self.ttl = int(self.expires_on - self.global_gen_time)

    def __post_init__(self):
        self.keyscope_hex = self.get_system_type_value()
        if isinstance(self.entropy_difficulty, int) and self.entropy_difficulty < 1024:
            raise ValueError("entropy_difficulty as int must be >= 1024")
        if self.expires_on < self.global_gen_time:
            raise ValueError("expires_on must be greater than global_gen_time")
        if self.counter < 0 or self.counter > 2**32 - 1:
            raise ValueError("counter must be between 0 and 2^32-1")
        if not self.system_fingerprint_hash:
            raise ValueError("system_fingerprint_hash must be a non-empty string")
        if not self.global_key_content:
            raise ValueError("global_key_content must be a non-empty string")
        if not self.key_uuid:
            raise ValueError("key_uuid must be a non-empty string")

    def to_dict(self) -> dict:
        return asdict(self)
