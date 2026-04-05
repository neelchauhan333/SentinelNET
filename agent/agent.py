# agent/agent.py
"""
SentinelNet Agent - Enhanced Monitoring
✅ Fixed duplicate event IDs
✅ Optimized file tracking
✅ Better error handling
✅ API Key security
✅ Logging system
"""

import time
import logging
import requests
import socket
import uuid
import psutil
import os
import random
from datetime import datetime
from pathlib import Path
import threading
import sys

# ── Config (import from backend if running together, else inline) ──
try:
    sys.path.append(str(Path(__file__).parent.parent))
    from backend.config import BACKEND_URL, API_KEY, LOG_FILE, LOG_LEVEL
except ImportError:
    BACKEND_URL = "http://127.0.0.1:8000"
    API_KEY     = "sentinel123"
    LOG_FILE    = "sentinelnet.log"
    LOG_LEVEL   = "INFO"

API_URL = f"{BACKEND_URL}/log_event"
HEADERS = {"x-api-key": API_KEY, "Content-Type": "application/json"}

# ── Logging ────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("sentinelnet.agent")

# ── Device identity ────────────────────────────────────────────────
DEVICE_ID = hex(uuid.getnode())
HOSTNAME  = socket.gethostname()

logger.info(f"Agent starting | Device ID: {DEVICE_ID} | Hostname: {HOSTNAME}")

# Track known processes and files
known_processes = set()
known_files     = set()


def send_event(event_type, data, severity="LOW"):
    """
    Send event to backend with API key header
    ✅ Unique event IDs using random suffix
    """
    event = {
        "event_id":   f"{event_type}-{int(time.time())}-{random.randint(1000, 9999)}",
        "device_id":  DEVICE_ID,
        "event_type": event_type,
        "event_time": str(datetime.now()),
        "event_data": data,
        "severity":   severity
    }
    
    try:
        r = requests.post(API_URL, json=event, headers=HEADERS, timeout=5)
        if r.status_code == 200:
            logger.info(f"Event sent: {event_type}")
            print(f"[✓] Event sent: {event_type}")
        else:
            logger.warning(f"Backend returned {r.status_code} for event {event_type}")
            print(f"[✗] Backend error: {r.status_code}")
    except requests.exceptions.ConnectionError:
        logger.error("Cannot connect to backend")
        print("[✗] Cannot connect to backend")
    except Exception as e:
        logger.error(f"send_event error: {str(e)}")
        print(f"[✗] Error: {e}")


# ========== MONITOR 1: USB Devices ==========

def monitor_usb():
    """Monitor USB insertions"""
    logger.info("USB monitor started")
    print("[Monitor] USB monitoring started")
    
    known_drives = set(psutil.disk_partitions())
    
    while True:
        try:
            current_drives = set(psutil.disk_partitions())
            new_drives = current_drives - known_drives
            
            for drive in new_drives:
                if 'removable' in drive.opts.lower() or drive.fstype:
                    logger.warning(f"USB detected: {drive.device}")
                    print(f"[!] USB DETECTED: {drive.device}")
                    
                    send_event(
                        "USB_INSERTED",
                        {
                            "device":     drive.device,
                            "mountpoint": drive.mountpoint,
                            "fstype":     drive.fstype,
                            "hostname":   HOSTNAME
                        },
                        severity="MEDIUM"
                    )
            
            known_drives = current_drives
            time.sleep(2)
            
        except Exception as e:
            logger.error(f"USB monitor error: {str(e)}")
            time.sleep(5)


# ========== MONITOR 2: Suspicious Processes ==========

def monitor_processes():
    """Monitor for suspicious processes"""
    logger.info("Process monitor started")
    print("[Monitor] Process monitoring started")
    
    global known_processes
    
    suspicious_keywords = [
        'hack', 'crack', 'keylog', 'backdoor', 'trojan',
        'mimikatz', 'metasploit', 'nmap'
    ]
    
    while True:
        try:
            current_processes = set()
            
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_name = proc.info['name'].lower()
                    current_processes.add(proc_name)
                    
                    if proc_name not in known_processes:
                        is_suspicious = any(keyword in proc_name for keyword in suspicious_keywords)
                        
                        if is_suspicious:
                            logger.warning(f"Suspicious process detected: {proc.info['name']}")
                            print(f"[!] SUSPICIOUS PROCESS: {proc.info['name']}")
                            
                            send_event(
                                "SUSPICIOUS_PROCESS",
                                {
                                    "process_name": proc.info['name'],
                                    "pid":          proc.info['pid'],
                                    "path":         proc.info['exe'] or "Unknown",
                                    "reason":       "Suspicious keyword detected"
                                },
                                severity="HIGH"
                            )
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            known_processes = current_processes
            time.sleep(10)
            
        except Exception as e:
            logger.error(f"Process monitor error: {str(e)}")
            time.sleep(10)


# ========== MONITOR 3: File System (Optimized) ==========

def monitor_files():
    """
    Monitor Downloads for new executables
    ✅ Optimized: Tracks files to avoid duplicates
    """
    logger.info("File monitor started")
    print("[Monitor] File monitoring started")
    
    global known_files
    
    user_home    = Path.home()
    watch_folders = [user_home / "Downloads"]
    
    dangerous_exts = ['.exe', '.bat', '.cmd', '.vbs', '.ps1', '.dll', '.scr']
    
    # Initialize: Remember all existing files
    for folder in watch_folders:
        if folder.exists():
            for file in folder.iterdir():
                if file.is_file():
                    known_files.add(str(file))
    
    logger.info(f"Tracking {len(known_files)} existing files")
    print(f"[Monitor] Tracking {len(known_files)} existing files")
    
    while True:
        try:
            for folder in watch_folders:
                if folder.exists():
                    for file in folder.iterdir():
                        if file.is_file() and str(file) not in known_files:
                            
                            if file.suffix.lower() in dangerous_exts:
                                logger.warning(f"New executable detected: {file.name}")
                                print(f"[!] NEW EXECUTABLE: {file.name}")
                                
                                send_event(
                                    "NEW_EXECUTABLE",
                                    {
                                        "filename":  file.name,
                                        "path":      str(file),
                                        "extension": file.suffix,
                                        "folder":    folder.name
                                    },
                                    severity="MEDIUM"
                                )
                            
                            known_files.add(str(file))
            
            time.sleep(30)
            
        except Exception as e:
            logger.error(f"File monitor error: {str(e)}")
            time.sleep(30)


# ========== MAIN ==========

def main():
    """Start all monitors"""
    
    print("\n" + "="*60)
    print(" SentinelNet Agent - Enhanced Monitoring")
    print("="*60)
    print(f" Device:    {HOSTNAME}")
    print(f" Device ID: {DEVICE_ID}")
    print(f" Backend:   {API_URL}")
    print(f" Log file:  {LOG_FILE}")
    print("="*60 + "\n")
    
    # Send startup event
    send_event(
        "AGENT_STARTED",
        {
            "hostname": HOSTNAME,
            "os":       os.name,
            "version":  "2.0"
        },
        severity="LOW"
    )
    
    # Start monitors in threads
    threads = [
        threading.Thread(target=monitor_usb,       daemon=True, name="USB Monitor"),
        threading.Thread(target=monitor_processes,  daemon=True, name="Process Monitor"),
        threading.Thread(target=monitor_files,      daemon=True, name="File Monitor")
    ]
    
    for thread in threads:
        thread.start()
        print(f"[✓] {thread.name} started")
    
    print("\n[Agent] All monitors active. Press Ctrl+C to stop.\n")
    
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        logger.info("Agent stopped by user")
        print("\n[Agent] Shutting down...")


if __name__ == "__main__":
    main()