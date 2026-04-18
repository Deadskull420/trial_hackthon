from __future__ import annotations

from random import randint
from typing import Dict

from can_bus import CANMessage


class ChargerSimulator:
    def __init__(self, charger_id: str = "CHG-PORT-77") -> None:
        self.charger_id = charger_id

    def auth_response(self, accepted: bool, reason: str = "ok") -> CANMessage:
        payload: Dict = {
            "type": "auth_response",
            "accepted": accepted,
            "reason": reason,
            "charger_id": self.charger_id,
        }
        return CANMessage(
            msg_id=0x110,
            source="CHARGER",
            destination="EV",
            payload=payload,
            is_malicious=not accepted and reason != "ok",
        )

    def power_delivery(self, degraded_mode: bool) -> CANMessage:
        delivered_kw = randint(6, 18) if degraded_mode else randint(50, 100)
        payload: Dict = {
            "type": "power_delivery",
            "mode": "degraded_safe_mode" if degraded_mode else "normal",
            "delivered_kw": delivered_kw,
        }
        return CANMessage(
            msg_id=0x111,
            source="CHARGER",
            destination="EV",
            payload=payload,
        )
