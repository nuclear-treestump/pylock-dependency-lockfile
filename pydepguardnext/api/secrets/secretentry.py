import time
from typing import Optional, Dict, Any
import threading
from pydepguardnext.api.log.logit import logit

logslug = "api.secrets.secretentry"

class SecretEntry:
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
        self._secrets[name] = entry

    def get(self, name: str) -> Optional[str]:
        entry = self._secrets.get(name)
        if not entry:
            return None
        value = entry.get()
        if entry.access_id:
            logit(f"[secrets] Accessed '{name}' (id: {entry.access_id})", "s", source="PyDepSecMap")
        if entry.is_expired():
            logit(f"[secrets] Expired '{name}'", "w", source="PyDepSecMap")
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

