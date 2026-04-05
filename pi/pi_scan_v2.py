# pi/pi_scan_v2.py
"""
SentinelNet Network Scanner v2 - Optimized
✅ MAC-based device_id (stable across IP changes)
✅ Faster scanning (multi-threaded)
✅ Better device detection
✅ API Key security
✅ Logging system
"""

import socket
import logging
import requests
from datetime import datetime
import subprocess
import platform
import json
from getmac import get_mac_address
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import re
import sys

# ── Config ─────────────────────────────────────────────────────────
try:
    sys.path.append(str(Path(__file__).parent.parent))
    from backend.config import BACKEND_URL, API_KEY, LOG_FILE, LOG_LEVEL
except ImportError:
    BACKEND_URL = "http://127.0.0.1:8000"
    API_KEY     = "sentinel123"
    LOG_FILE    = "sentinelnet.log"
    LOG_LEVEL   = "INFO"

API_URL = f"{BACKEND_URL}/pi_scan"
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
logger = logging.getLogger("sentinelnet.scanner")

# ── MAC vendor database (top manufacturers) ────────────────────────
MAC_VENDORS = {
    "AC:DE:48": "Apple",        "3C:22:FB": "Apple",    "F0:18:98": "Apple",
    "28:CF:E9": "Apple",        "A4:5E:60": "Apple",    "88:66:5A": "Apple",
    "AC:37:43": "Samsung",      "E8:50:8B": "Samsung",  "34:AA:8B": "Samsung",
    "48:D6:D5": "Google",       "3C:5A:B4": "Google",   "F4:F5:D8": "Google",
    "DC:A6:32": "Raspberry Pi", "B8:27:EB": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi", "28:CD:C1": "Raspberry Pi",
    "18:4F:32": "Dell",         "D4:AE:52": "Dell",     "00:1A:A0": "Dell",
    "00:10:83": "HP",           "00:11:0A": "HP",        "00:12:79": "HP",
    "00:90:4C": "TP-Link",      "50:C7:BF": "TP-Link",
    "00:18:E7": "Netgear",      "E0:46:9A": "Netgear",
}


def get_local_network():
    """Get local network base"""
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    base = ".".join(local_ip.split(".")[:3])
    return base, local_ip


def ping(ip):
    """Quick ping check"""
    param   = "-n" if platform.system().lower() == "windows" else "-c"
    timeout = "-w" if platform.system().lower() == "windows" else "-W"
    command = ["ping", param, "1", timeout, "500", ip]
    try:
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2) == 0
    except Exception:
        return False


def get_mac_for_ip(ip):
    """Get MAC address using multiple methods"""
    # Method 1: getmac library
    try:
        mac = get_mac_address(ip=ip)
        if mac and mac != "00:00:00:00:00:00":
            return mac.upper()
    except Exception:
        pass
    
    # Method 2: Parse ARP table
    try:
        if platform.system().lower() == "windows":
            result = subprocess.check_output(f"arp -a {ip}", shell=True, timeout=2).decode()
        else:
            result = subprocess.check_output(f"arp -n {ip}", shell=True, timeout=2).decode()
        
        mac_pattern = r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"
        match = re.search(mac_pattern, result)
        if match:
            return match.group(0).upper().replace("-", ":")
    except Exception:
        pass
    
    return "Unknown"


def identify_vendor(mac):
    """Identify manufacturer from MAC"""
    if mac == "Unknown":
        return "Unknown"
    prefix = mac[:8]
    return MAC_VENDORS.get(prefix, "Unknown Vendor")


def guess_device_type(hostname, vendor):
    """Guess device type"""
    hostname_lower = hostname.lower()
    vendor_lower   = vendor.lower()
    
    if any(x in hostname_lower for x in ["android", "phone", "mobile", "samsung", "xiaomi"]):
        return "Mobile Phone"
    elif any(x in hostname_lower for x in ["iphone", "ipad", "mac"]):
        return "Apple Device"
    elif any(x in hostname_lower for x in ["desktop", "pc", "laptop", "workstation"]):
        return "Computer"
    elif any(x in hostname_lower for x in ["router", "gateway", "modem"]):
        return "Router"
    elif "pi" in hostname_lower or "raspberry" in vendor_lower:
        return "Raspberry Pi"
    
    if "apple" in vendor_lower:
        return "Apple Device"
    elif any(x in vendor_lower for x in ["samsung", "xiaomi", "huawei"]):
        return "Mobile Device"
    elif "raspberry" in vendor_lower:
        return "Raspberry Pi"
    elif any(x in vendor_lower for x in ["tp-link", "netgear", "linksys"]):
        return "Router"
    
    return "Unknown Device"


def scan_single_ip(ip):
    """Scan a single IP (for parallel execution)"""
    if not ping(ip):
        return None
    
    try:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = "Unknown"
        
        mac         = get_mac_for_ip(ip)
        vendor      = identify_vendor(mac)
        device_type = guess_device_type(hostname, vendor)
        
        # ✅ Use MAC as device_id (stable across IP changes)
        device_id = mac.replace(":", "").upper() if mac != "Unknown" else ip.replace(".", "")
        
        device = {
            "device_id":      device_id,
            "ip_address":     ip,
            "mac_address":    mac,
            "hostname":       hostname,
            "vendor":         vendor,
            "device_type":    device_type,
            "last_seen":      str(datetime.now()),
            "blocked_status": False
        }
        
        return device
        
    except Exception as e:
        logger.error(f"scan_single_ip error for {ip}: {str(e)}")
        return None


def scan_network():
    """Scan network using parallel threads (faster)"""
    base, local_ip = get_local_network()
    logger.info(f"Starting network scan: {base}.0/24 | Local IP: {local_ip}")
    print(f"[+] Scanning: {base}.0/24")
    print(f"[+] Your IP: {local_ip}")
    print(f"[+] Using parallel scanning for speed...\n")
    
    devices = []
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = []
        for i in range(1, 255):
            ip = f"{base}.{i}"
            future = executor.submit(scan_single_ip, ip)
            futures.append(future)
        
        completed = 0
        for future in futures:
            completed += 1
            if completed % 25 == 0:
                print(f"[*] Progress: {completed}/254 ({len(devices)} found)")
            
            try:
                result = future.result(timeout=5)
                if result:
                    devices.append(result)
                    print(f"[+] Found: {result['ip_address']:15} | {result['hostname']:20} | {result['device_type']}")
            except Exception:
                pass
    
    logger.info(f"Scan complete: {len(devices)} devices found")
    return devices


def send_to_backend(devices):
    """Send results to backend with API key header"""
    if not devices:
        logger.warning("No devices found — nothing sent to backend")
        print("\n[-] No devices found")
        return
    
    try:
        logger.info(f"Sending {len(devices)} devices to backend")
        print(f"\n[*] Sending {len(devices)} devices to backend...")
        r = requests.post(API_URL, json=devices, headers=HEADERS, timeout=10)
        
        if r.status_code == 200:
            logger.info("Scan data sent successfully")
            print("[+] ✓ Data sent successfully")
        else:
            logger.warning(f"Backend returned {r.status_code}")
            print(f"[-] Backend error: {r.status_code}")
    except requests.exceptions.ConnectionError:
        logger.error("Cannot connect to backend")
        print("[-] Cannot connect to backend")
        print("[-] Make sure backend is running:")
        print("    uvicorn backend.main:app --reload")
    except Exception as e:
        logger.error(f"send_to_backend error: {str(e)}")
        print(f"[-] Error: {e}")


if __name__ == "__main__":
    print("="*60)
    print(" SentinelNet Network Scanner v2")
    print("="*60)
    
    devices = scan_network()
    
    print("\n" + "="*60)
    print(f" Found {len(devices)} devices")
    print("="*60)
    
    # Save to file
    Path("pi/scan_results.json").write_text(json.dumps(devices, indent=2))
    print("[+] Results saved to: pi/scan_results.json")
    
    # Send to backend
    send_to_backend(devices)