# backend/risk_engine.py
from datetime import datetime
from typing import List, Dict

# Simple rule-based risk engine
# Input:
#   device: dict (device record)
#   events: list of event dicts (all events from DB)
# Returns:
#   score (0-100), reasons (list of strings)

def calculate_risk(device: Dict, events: List[Dict]) -> (int, List[str]):
    reasons = []
    score = 0

    dev_id = device.get("device_id")

    # Gather events for this device (most recent first)
    dev_events = [e for e in events if e.get("device_id") == dev_id]
    recent_count = len(dev_events)

    # Rule 1: New device (no events and last_seen within short time)
    if recent_count == 0:
        # new device: moderate attention
        score += 10
        reasons.append("New device detected")

    # Rule 2: Many events recently
    if recent_count >= 5:
        score += 25
        reasons.append(f"{recent_count} events detected")

    # Rule 3: USB malware / suspicious USB events
    for e in dev_events:
        t = str(e.get("event_type", "")).upper()
        data = str(e.get("event_data", "")).upper()
        if "MALWARE" in t or "MALWARE" in data or "SUSPICIOUS" in t:
            score += 40
            reasons.append("USB / malware activity")
            break

    # Rule 4: Port scanning or network scanning behavior
    for e in dev_events:
        t = str(e.get("event_type", "")).upper()
        if "PORT_SCAN" in t or "SCAN" in t:
            score += 50
            reasons.append("Port scanning behavior")
            break

    # Rule 5: Frequent reconnects (same event repeated)
    if recent_count >= 3:
        # look for repeating event_data patterns (simple heuristic)
        seen = {}
        repeats = 0
        for e in dev_events:
            key = str(e.get("event_type", "")) + "::" + str(e.get("event_data", ""))
            seen[key] = seen.get(key, 0) + 1
            if seen[key] > 1:
                repeats += 1
        if repeats >= 2:
            score += 20
            reasons.append("Frequent reconnections / repeated events")

    # Rule 6: If device was blocked manually earlier — reduce score range
    if device.get("blocked_status"):
        reasons.append("Already blocked (manual or auto)")
        score = min(score, 100)

    # Clamp score
    if score > 100:
        score = 100

    # If no specific reason, add 'baseline'
    if not reasons:
        reasons.append("Baseline monitoring")

    # Return integer score and unique reasons
    return int(score), list(dict.fromkeys(reasons))
