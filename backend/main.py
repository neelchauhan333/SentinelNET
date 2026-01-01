# backend/main.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import json
from pathlib import Path
from datetime import datetime

# local modules
from . import blockchain
from .risk_engine import calculate_risk

app = FastAPI(title="SentinelNet Backend API")

# CORS (allow dashboard)
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_FILE = Path("backend/database.json")
BLOCKCHAIN_FILE = Path("backend/blockchain.json")

# Models
class Device(BaseModel):
    device_id: str
    ip_address: str
    mac_address: str
    hostname: str
    last_seen: str
    blocked_status: bool = False
    risk_score: int = 0
    risk_reasons: List[str] = []
    risk_history: List[dict] = []

class Event(BaseModel):
    event_id: str
    device_id: str
    event_type: str
    event_time: str
    event_data: dict

# Ensure DB exists
if not DATABASE_FILE.exists() or DATABASE_FILE.read_text().strip() == "":
    DATABASE_FILE.write_text(json.dumps({"devices": [], "events": []}, indent=4))

# Ensure blockchain exists
blockchain.ensure_chain()

# Utility: read/write db
def read_db():
    return json.loads(DATABASE_FILE.read_text())

def write_db(data):
    DATABASE_FILE.write_text(json.dumps(data, indent=4))

# Recalculate risk for a device_id and update DB
def recalc_risk_for_device(device_id: str):
    db = read_db()
    devices = db.get("devices", [])
    events = db.get("events", [])
    # find device
    for d in devices:
        if d.get("device_id") == device_id:
            score, reasons = calculate_risk(d, events)
            # update device
            d["risk_score"] = score
            d["risk_reasons"] = reasons
            # append to history
            history = d.get("risk_history", [])
            history.append({"time": str(datetime.now()), "score": score})
            # keep last 50
            d["risk_history"] = history[-50:]
            # auto-block if >= 70
            if score >= 70 and not d.get("blocked_status", False):
                d["blocked_status"] = True
                # create an event for auto-block
                new_event = {
                    "event_id": f"auto-block-{device_id}-{int(datetime.now().timestamp())}",
                    "device_id": device_id,
                    "event_type": "AUTO_BLOCK",
                    "event_time": str(datetime.now()),
                    "event_data": {"reason": "Risk score threshold", "score": score}
                }
                events.append(new_event)
                db["events"] = events
                # log to blockchain
                blockchain.add_block({"action": "auto_block", "device_id": device_id, "score": score, "time": str(datetime.now())})
            write_db(db)
            return d
    return None

# API Endpoints
@app.get("/health")
def health_check():
    return {"status": "ok", "message": "SentinelNet Backend Running"}

@app.post("/pi_scan")
def receive_pi_scan(devices: List[Device]):
    db = read_db()
    existing = db.get("devices", [])
    # merge devices: if device_id exists update last_seen, else append
    for device in devices:
        found = False
        for e in existing:
            if e.get("device_id") == device.device_id:
                # update fields
                e.update(device.dict())
                found = True
                break
        if not found:
            # ensure risk fields
            rec = device.dict()
            rec.setdefault("risk_score", 0)
            rec.setdefault("risk_reasons", [])
            rec.setdefault("risk_history", [])
            existing.append(rec)
    db["devices"] = existing
    write_db(db)
    # Recalc risk for all devices we received
    for device in devices:
        recalc_risk_for_device(device.device_id)
    return {"message": "Scan saved successfully", "device_count": len(devices)}

@app.post("/log_event")
def receive_event(event: Event):
    db = read_db()
    events = db.get("events", [])
    events.append(event.dict())
    db["events"] = events
    write_db(db)
    # recalc risk for that device
    recalc_risk_for_device(event.device_id)
    return {"message": "Event logged successfully"}

@app.get("/database")
def get_database():
    return read_db()

@app.get("/risk_report")
def get_risk_report():
    db = read_db()
    devices = db.get("devices", [])
    # Prepare summary and top risky devices
    safe = suspicious = high = 0
    for d in devices:
        s = int(d.get("risk_score", 0))
        if s >= 70:
            high += 1
        elif s >= 40:
            suspicious += 1
        else:
            safe += 1
    # sort devices by risk desc
    top = sorted(devices, key=lambda x: x.get("risk_score", 0), reverse=True)
    return {
        "summary": {"safe": safe, "suspicious": suspicious, "high": high, "total": len(devices)},
        "top_devices": top[:10]
    }

@app.post("/block_device/{device_id}")
def block_device(device_id: str):
    db = read_db()
    devices = db.get("devices", [])
    events = db.get("events", [])
    for d in devices:
        if d.get("device_id") == device_id:
            if d.get("blocked_status"):
                raise HTTPException(status_code=400, detail="Device already blocked")
            d["blocked_status"] = True
            # log event
            ev = {
                "event_id": f"manual-block-{device_id}-{int(datetime.now().timestamp())}",
                "device_id": device_id,
                "event_type": "MANUAL_BLOCK",
                "event_time": str(datetime.now()),
                "event_data": {"reason": "Manual block from dashboard"}
            }
            events.append(ev)
            db["events"] = events
            write_db(db)
            blockchain.add_block({"action": "manual_block", "device_id": device_id, "time": str(datetime.now())})
            return {"message": "Device blocked"}
    raise HTTPException(status_code=404, detail="Device not found")
