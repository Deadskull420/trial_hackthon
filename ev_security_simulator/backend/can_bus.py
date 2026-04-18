from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Dict, List


@dataclass
class CANMessage:
    msg_id: int
    source: str
    destination: str
    payload: Dict
    is_malicious: bool = False
    protocol: str = "CAN"
    timestamp: str = ""

    def to_dict(self) -> Dict:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        return asdict(self)


class CANBus:
    def __init__(self) -> None:
        self._history: List[Dict] = []

    def transmit(self, message: CANMessage) -> Dict:
        serialized = message.to_dict()
        self._history.append(serialized)
        return serialized

    def history(self, limit: int = 200) -> List[Dict]:
        return self._history[-limit:]
