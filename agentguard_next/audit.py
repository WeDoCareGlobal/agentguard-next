import hashlib
import hmac
import json
from dataclasses import dataclass, field

def canonical(event: dict) -> bytes:
    return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

@dataclass
class AuditChain:
    key: bytes
    entries: list[dict] = field(default_factory=list)

    def append(self, event: dict) -> str:
        if not self.key:
            raise ValueError("audit signing key required")
        prev = self.entries[-1]["digest"] if self.entries else ""
        payload = canonical({"prev": prev, "event": event})
        digest = hmac.new(self.key, payload, hashlib.sha256).hexdigest()
        self.entries.append({"prev": prev, "event": dict(event), "digest": digest})
        return digest

    def verify(self) -> bool:
        prev = ""
        for entry in self.entries:
            if entry["prev"] != prev:
                return False
            expected = hmac.new(self.key, canonical({"prev": prev, "event": entry["event"]}), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(entry["digest"], expected):
                return False
            prev = entry["digest"]
        return True
