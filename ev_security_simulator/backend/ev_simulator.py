from __future__ import annotations

from random import randint
from typing import Dict

from can_bus import CANMessage


class EVSimulator:
    def __init__(self, vehicle_id: str = "EV-ALPHA-001") -> None:
        self.vehicle_id = vehicle_id
        self.soc = 42

    def generate_handshake(self) -> CANMessage:
        payload: Dict = {
            "type": "auth_request",
            "vehicle_id": self.vehicle_id,
            "nonce": randint(100000, 999999),
        }
        return CANMessage(
            msg_id=0x100,
            source="EV",
            destination="CHARGER",
            payload=payload,
        )

    def telemetry(self) -> CANMessage:
        self.soc = min(100, self.soc + 1)
        payload: Dict = {
            "type": "telemetry",
            "soc": self.soc,
            "battery_temp_c": randint(26, 34),
            "requested_kw": randint(45, 65),
        }
        return CANMessage(
            msg_id=0x101,
            source="EV",
            destination="CHARGER",
            payload=payload,
        )
