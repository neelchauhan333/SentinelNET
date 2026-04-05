# pi/auto_scanner.py
"""
Auto-Scanner for SentinelNet
Runs network scan automatically every X minutes
"""

import time
import subprocess
import sys
from pathlib import Path
from datetime import datetime

# Configuration
SCAN_INTERVAL = 300  # seconds (300 = 5 minutes)
SCANNER_SCRIPT = Path(__file__).parent / "pi_scan_v2.py"

def run_scan():
    """Run network scan"""
    try:
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Starting network scan...")
        
        # Run scanner
        result = subprocess.run(
            [sys.executable, str(SCANNER_SCRIPT)],
            capture_output=True,
            text=True,
            timeout=180  # 3 minute timeout
        )
        
        if result.returncode == 0:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ✓ Scan completed successfully")
        else:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ✗ Scan failed")
            
    except subprocess.TimeoutExpired:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ✗ Scan timeout")
    except Exception as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ✗ Error: {e}")

def main():
    """Main loop"""
    print("="*60)
    print(" SentinelNet Auto-Scanner")
    print("="*60)
    print(f" Scan Interval: {SCAN_INTERVAL} seconds ({SCAN_INTERVAL//60} minutes)")
    print(f" Scanner: {SCANNER_SCRIPT.name}")
    print("="*60)
    print(" Press Ctrl+C to stop\n")
    
    # Run first scan immediately
    run_scan()
    
    # Then run periodically
    try:
        while True:
            print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Next scan in {SCAN_INTERVAL//60} minutes...")
            time.sleep(SCAN_INTERVAL)
            run_scan()
            
    except KeyboardInterrupt:
        print("\n\n[Auto-Scanner] Stopped by user")

if __name__ == "__main__":
    main()