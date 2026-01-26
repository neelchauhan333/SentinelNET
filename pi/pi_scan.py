import socket
import requests
from datetime import datetime
import subprocess
import platform

API_URL = "http://127.0.0.1:8000/pi_scan"

def get_local_network():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    base = ".".join(local_ip.split(".")[:3])
    return base, local_ip

def ping(ip):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", ip]
    return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def scan_network():
    base, local_ip = get_local_network()
    print(f"[+] Scanning network: {base}.0/24")

    devices = []

    for i in range(1, 255):
        ip = f"{base}.{i}"
        if ping(ip):
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = "Unknown"

            device = {
                "device_id": ip.replace(".", ""),
                "ip_address": ip,
                "mac_address": "Unknown",
                "hostname": hostname,
                "last_seen": str(datetime.now()),
                "blocked_status": False
            }
            devices.append(device)

    return devices

def send_to_backend(devices):
    if not devices:
        print("[-] No devices found")
        return

    r = requests.post(API_URL, json=devices)
    if r.status_code == 200:
        print("[+] Devices sent successfully")
    else:
        print("[-] Backend error:", r.text)

if __name__ == "__main__":
    devices = scan_network()
    print(f"[+] Found {len(devices)} devices")
    send_to_backend(devices)
