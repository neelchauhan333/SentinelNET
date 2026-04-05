# backend/risk_engine.py
"""
Risk Engine for SentinelNet - WITH ML INTEGRATION
Combines rule-based + ML anomaly detection
"""

from datetime import datetime
from typing import List, Dict, Tuple

def calculate_risk(device: Dict, events: List[Dict]) -> Tuple[int, List[str]]:
    """
    Calculate risk score using rules + ML
    
    Args:
        device: Device record
        events: List of events for this device
    
    Returns:
        (risk_score, risk_reasons)
    """
    
    reasons = []
    rule_score = 0
    
    device_id = device.get("device_id")
    device_events = [e for e in events if e.get("device_id") == device_id]
    event_count = len(device_events)
    
    # ========== RULE-BASED SCORING ==========
    
    # Rule 1: New device
    if event_count == 0:
        rule_score += 10
        reasons.append("New device detected")
    
    # Rule 2: Many events
    if event_count >= 10:
        rule_score += 30
        reasons.append(f"High activity ({event_count} events)")
    elif event_count >= 5:
        rule_score += 15
        reasons.append(f"{event_count} events detected")
    
    # Rule 3: Malware/suspicious activity
    for event in device_events:
        event_type = str(event.get("event_type", "")).upper()
        event_data = str(event.get("event_data", "")).upper()
        
        if "MALWARE" in event_type or "MALWARE" in event_data or "SUSPICIOUS" in event_type:
            rule_score += 40
            reasons.append("Malware/suspicious activity detected")
            break
    
    # Rule 4: Port scanning
    for event in device_events:
        event_type = str(event.get("event_type", "")).upper()
        if "PORT_SCAN" in event_type or "SCAN" in event_type:
            rule_score += 50
            reasons.append("Port scanning detected")
            break
    
    # Rule 5: Multiple executables
    executable_events = [
        e for e in device_events 
        if "EXECUTABLE" in str(e.get("event_type", "")).upper()
    ]
    if len(executable_events) >= 5:
        rule_score += 30
        reasons.append(f"{len(executable_events)} new executables detected")
    elif len(executable_events) >= 3:
        rule_score += 15
        reasons.append(f"{len(executable_events)} new executables")
    
    # Rule 6: Suspicious processes
    suspicious_events = [
        e for e in device_events
        if "SUSPICIOUS_PROCESS" in str(e.get("event_type", "")).upper()
    ]
    if len(suspicious_events) >= 1:
        rule_score += 35
        reasons.append(f"Suspicious process detected")
    
    # Rule 7: Multiple USB insertions
    usb_events = [
        e for e in device_events
        if "USB" in str(e.get("event_type", "")).upper()
    ]
    if len(usb_events) >= 3:
        rule_score += 25
        reasons.append(f"Multiple USB insertions ({len(usb_events)})")
    
    # Cap rule score at 100
    rule_score = min(rule_score, 100)
    
    # ========== ML ANOMALY DETECTION ==========
    
    ml_score = 0
    ml_reason = ""
    
    try:
        # Import ML detector
        from .ml_detector import get_ml_score
        
        # Get ML anomaly score
        ml_score, ml_reason = get_ml_score(device, device_events)
        
        if ml_score > 0:
            reasons.append(ml_reason)
        
    except Exception as e:
        # ML failed, just use rules
        print(f"[ML Error] {e}")
        ml_score = 0
    
    # ========== COMBINE SCORES ==========
    
    # Weighted combination: 70% rules, 30% ML
    final_score = int((rule_score * 0.7) + (ml_score * 0.3))
    
    # Cap at 100
    final_score = min(final_score, 100)
    
    # Default reason if none
    if not reasons:
        reasons.append("Baseline monitoring")
    
    return final_score, list(set(reasons))  # Remove duplicates