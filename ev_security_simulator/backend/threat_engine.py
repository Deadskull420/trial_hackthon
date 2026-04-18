from __future__ import annotations

from typing import Dict, List, Optional


THREATS: List[Dict] = [
    {
        "name": "Juice Jacking",
        "slug": "juice_jacking",
        "entry_point": "Charging cable data line",
        "attack_path": ["Data interception", "Payload injection"],
        "target_systems": ["Battery Management System", "User Data"],
    },
    {
        "name": "Identity Spoofing",
        "slug": "identity_spoofing",
        "entry_point": "Forged EV identity packet",
        "attack_path": ["Credential replay", "Session hijack"],
        "target_systems": ["Authentication Service", "Billing Account"],
    },
    {
        "name": "Mutual Auth Bypass",
        "slug": "auth_bypass",
        "entry_point": "Handshake downgrade",
        "attack_path": ["Protocol tampering", "Trust-chain bypass"],
        "target_systems": ["Certificate Validation", "Charging Controller"],
    },
]


class ThreatEngine:
    def __init__(self) -> None:
        self.active_threat: Optional[Dict] = None

    def set_active(self, slug: str) -> Optional[Dict]:
        match = next((t for t in THREATS if t["slug"] == slug), None)
        self.active_threat = match
        return match

    def clear(self) -> None:
        self.active_threat = None

    def catalog(self) -> List[Dict]:
        return THREATS

    def mutate_message(self, message: Dict) -> Dict:
        if not self.active_threat:
            return message

        slug = self.active_threat["slug"]

        if slug == "juice_jacking" and message["payload"].get("type") == "telemetry":
            message["source"] = "MITM"
            message["is_malicious"] = True
            message["payload"]["unexpected_blob"] = "ff3a9d-malicious-payload"
        elif slug == "identity_spoofing" and message["payload"].get("type") == "auth_request":
            message["payload"]["vehicle_id"] = "EV-FAKE-31337"
            message["is_malicious"] = True
        elif slug == "auth_bypass" and message["payload"].get("type") == "auth_request":
            message["payload"]["force_bypass"] = True
            message["is_malicious"] = True

        return message
