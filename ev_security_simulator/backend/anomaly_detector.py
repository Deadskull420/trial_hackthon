from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass
class Detection:
    detected: bool
    confidence: float
    reason: str
    severity: str


class AnomalyDetector:
    def __init__(self) -> None:
        self._recent_ids: List[int] = []

    def inspect(self, message: Dict, auth_failures: int = 0) -> Detection:
        confidence = 0.05
        reasons: List[str] = []

        msg_id = message.get("msg_id", 0)
        payload = message.get("payload", {})
        source = message.get("source")

        if msg_id > 0x7FF:
            confidence += 0.45
            reasons.append("abnormal_can_identifier")

        if payload.get("unexpected_blob"):
            confidence += 0.4
            reasons.append("unexpected_payload")

        if auth_failures > 0:
            confidence += min(0.45, auth_failures * 0.15)
            reasons.append("repeated_auth_failures")

        if source == "MITM":
            confidence += 0.5
            reasons.append("untrusted_source")

        self._recent_ids.append(msg_id)
        self._recent_ids = self._recent_ids[-30:]

        duplicate_ratio = self._recent_ids.count(msg_id) / len(self._recent_ids)
        if duplicate_ratio > 0.5:
            confidence += 0.2
            reasons.append("anomalous_repetition")

        confidence = min(0.99, confidence)

        if confidence >= 0.75:
            return Detection(True, confidence, ", ".join(reasons), "high")
        if confidence >= 0.4:
            return Detection(True, confidence, ", ".join(reasons), "medium")
        return Detection(False, confidence, ", ".join(reasons) or "normal", "low")
