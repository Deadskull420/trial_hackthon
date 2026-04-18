from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from anomaly_detector import AnomalyDetector
from auth_manager import AuthManager
from can_bus import CANBus
from charger_simulator import ChargerSimulator
from ev_simulator import EVSimulator
from threat_engine import ThreatEngine

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "config.yaml"
LOG_PATH = ROOT / "logs" / "events.log"


def load_config() -> Dict[str, Any]:
    with open(CONFIG_PATH, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)


config = load_config()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler(),
    ],
)

app = FastAPI(title="EV Security Simulator", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AttackRequest(BaseModel):
    threat_slug: str


class SimulationController:
    def __init__(self) -> None:
        self.can_bus = CANBus()
        self.ev = EVSimulator()
        self.charger = ChargerSimulator()
        self.threat_engine = ThreatEngine()
        self.auth = AuthManager()
        self.detector = AnomalyDetector()
        self.safe_mode = False
        self.running = False
        self.task: Optional[asyncio.Task] = None
        self.subscribers: List[asyncio.Queue] = []
        self.last_detection: Dict[str, Any] = {"risk": "Low", "detail": "No threats detected"}

    async def start(self) -> None:
        if self.running:
            return
        self.running = True
        self.task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self.running = False
        self.threat_engine.clear()
        if self.task:
            await asyncio.wait([self.task], timeout=1)

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=250)
        self.subscribers.append(q)
        return q

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        if queue in self.subscribers:
            self.subscribers.remove(queue)

    async def inject_attack(self, slug: str) -> Dict[str, Any]:
        threat = self.threat_engine.set_active(slug)
        if not threat:
            return {"status": "error", "message": "Threat slug not found"}
        logging.warning("Attack injected: %s", threat["name"])
        return {"status": "ok", "active_threat": threat}

    async def _broadcast(self, event: Dict[str, Any]) -> None:
        for queue in list(self.subscribers):
            if queue.full():
                _ = queue.get_nowait()
            await queue.put(event)

    async def _handle_message(self, msg: Dict) -> None:
        mutated = self.threat_engine.mutate_message(msg)

        if mutated["payload"].get("type") == "auth_request":
            if mutated["payload"].get("force_bypass"):
                self.auth.force_bypass()
                accepted, reason = True, "mutual_auth_bypassed"
            else:
                accepted, reason = self.auth.verify_request(mutated["payload"])

            response = self.can_bus.transmit(self.charger.auth_response(accepted, reason))
            await self._broadcast({"kind": "can_message", "data": response})

        detection = self.detector.inspect(mutated, auth_failures=self.auth.state.failed_attempts)
        action = "log_only"

        if detection.detected and detection.confidence >= config["security"]["high_confidence_threshold"]:
            action = "alert_and_restrict"
            self.safe_mode = True
        elif detection.detected and detection.confidence >= config["security"]["low_confidence_threshold"]:
            action = "alert_fail_operational"

        risk = "Low"
        if detection.severity == "medium":
            risk = "Medium"
        if detection.severity == "high":
            risk = "High"

        self.last_detection = {
            "risk": risk,
            "confidence": round(detection.confidence, 2),
            "reason": detection.reason,
            "action": action,
            "safe_mode": self.safe_mode,
        }

        event = {"kind": "detection", "data": self.last_detection}
        await self._broadcast({"kind": "can_message", "data": mutated})
        await self._broadcast(event)

        logging.info(json.dumps({"message": mutated, "detection": self.last_detection}))

    async def _loop(self) -> None:
        while self.running:
            handshake = self.can_bus.transmit(self.ev.generate_handshake())
            await self._handle_message(handshake)

            telemetry = self.can_bus.transmit(self.ev.telemetry())
            await self._handle_message(telemetry)

            power = self.can_bus.transmit(self.charger.power_delivery(self.safe_mode))
            await self._handle_message(power)

            await asyncio.sleep(config["simulation"]["tick_seconds"])


controller = SimulationController()


@app.get("/api/health")
async def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/api/threats")
async def threats() -> List[Dict]:
    return controller.threat_engine.catalog()


@app.get("/api/status")
async def status() -> Dict[str, Any]:
    return {
        "running": controller.running,
        "safe_mode": controller.safe_mode,
        "active_threat": controller.threat_engine.active_threat,
        "last_detection": controller.last_detection,
        "history": controller.can_bus.history(30),
    }


@app.post("/api/simulation/start")
async def start() -> Dict[str, str]:
    await controller.start()
    return {"status": "started"}


@app.post("/api/simulation/stop")
async def stop() -> Dict[str, str]:
    await controller.stop()
    return {"status": "stopped"}


@app.post("/api/attack/inject")
async def inject_attack(payload: AttackRequest) -> Dict[str, Any]:
    return await controller.inject_attack(payload.threat_slug)


@app.websocket("/ws/stream")
async def stream(websocket: WebSocket) -> None:
    await websocket.accept()
    queue = controller.subscribe()
    try:
        while True:
            event = await queue.get()
            await websocket.send_json(event)
    except WebSocketDisconnect:
        controller.unsubscribe(queue)
