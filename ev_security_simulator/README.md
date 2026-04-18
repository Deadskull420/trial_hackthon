# EV Security Simulator

A complete UI-based simulator for EV charging cybersecurity analysis using CAN message flow.

## Features
- FastAPI backend with EV↔Charger CAN simulation.
- Threat scenarios:
  - Juice jacking
  - Identity spoofing
  - Mutual authentication bypass
- Rule + anomaly based detection.
- Confidence-driven response:
  - Low confidence => log only
  - High confidence => alert + restrict (degraded safe mode)
- Safety-first behavior:
  - Never abruptly stops charging
  - Falls back to degraded charging mode
- Live UI dashboard with:
  - CAN message stream
  - Detection panel
  - Risk indicator
  - Start/stop and attack injection controls
- Structured threat modeling JSON output.
- Event logging to `logs/events.log`.

## Repository Structure

```text
ev_security_simulator/
│── backend/
│   ├── main.py
│   ├── ev_simulator.py
│   ├── charger_simulator.py
│   ├── can_bus.py
│   ├── threat_engine.py
│   ├── anomaly_detector.py
│   ├── auth_manager.py
│   └── requirements.txt
│
│── frontend/
│   ├── index.html
│   ├── app.js
│   └── styles.css
│
│── config/
│   └── config.yaml
│
│── logs/
│   └── events.log
│
│── run.sh
│── README.md
```

## Setup & Run

### Option 1: One command
```bash
cd ev_security_simulator
chmod +x run.sh
./run.sh
```

### Option 2: Manual startup
```bash
cd ev_security_simulator
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt

# terminal A
cd backend
uvicorn main:app --reload --host 127.0.0.1 --port 8000

# terminal B
cd frontend
python3 -m http.server 8080
```

Open dashboard: `http://127.0.0.1:8080`

## API Endpoints
- `GET /api/health`
- `GET /api/threats`
- `GET /api/status`
- `POST /api/simulation/start`
- `POST /api/simulation/stop`
- `POST /api/attack/inject` body: `{"threat_slug":"juice_jacking"}`
- `WS /ws/stream`

## Threat JSON Example
```json
{
  "name": "Juice Jacking",
  "entry_point": "Charging cable data line",
  "attack_path": ["Data interception", "Payload injection"],
  "target_systems": ["Battery Management System", "User Data"]
}
```

## Notes
- CAN traffic is mocked for lab/testing use.
- Optional protocol expansion can be implemented by adding additional message adapters.
