from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass
class AuthState:
    authenticated: bool = False
    failed_attempts: int = 0
    bypass_detected: bool = False


class AuthManager:
    def __init__(self) -> None:
        self.state = AuthState()
        self._trusted_ids = {"EV-ALPHA-001"}

    def verify_request(self, payload: Dict) -> tuple[bool, str]:
        vehicle_id = payload.get("vehicle_id")
        if vehicle_id not in self._trusted_ids:
            self.state.failed_attempts += 1
            return False, "identity_spoofing_detected"

        self.state.authenticated = True
        self.state.failed_attempts = 0
        return True, "ok"

    def force_bypass(self) -> None:
        self.state.bypass_detected = True
        self.state.authenticated = True

    def repeated_failures(self, threshold: int = 3) -> bool:
        return self.state.failed_attempts >= threshold
