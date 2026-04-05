# start_sentinelnet.py
"""
Start all SentinelNet components including dashboard server
"""

import subprocess
import sys
import time
import webbrowser
from pathlib import Path

def start_component(name, command, cwd=None):
    """Start a component in new terminal"""
    print(f"[+] Starting {name}...")
    
    if sys.platform == "win32":
        # Windows
        if cwd:
            subprocess.Popen(
                f'start cmd /k "title {name} && cd {cwd} && {command}"',
                shell=True
            )
        else:
            subprocess.Popen(
                f'start cmd /k "title {name} && {command}"',
                shell=True
            )
    else:
        # Linux/Mac
        subprocess.Popen(
            command,
            shell=True,
            cwd=cwd
        )
    
    time.sleep(2)

def main():
    print("="*60)
    print(" Starting SentinelNet System")
    print("="*60)
    
    # Start backend
    start_component(
        "Backend API",
        "uvicorn backend.main:app --reload"
    )
    
    # Start dashboard server
    start_component(
        "Dashboard Server",
        "python -m http.server 5500",
        cwd="dashboard"
    )
    
    # Start auto-scanner
    start_component(
        "Auto-Scanner",
        "python pi/auto_scanner.py"
    )
    
    # Start agent
    start_component(
        "Agent",
        "python agent/agent.py"
    )
    
    print("\n[✓] All components started!")
    print("\n" + "="*60)
    print(" SentinelNet is now running:")
    print("="*60)
    print(" • Backend API:   http://127.0.0.1:8000")
    print(" • API Docs:      http://127.0.0.1:8000/docs")
    print(" • Dashboard:     http://localhost:5500")
    print("="*60)
    print("\n[!] Opening dashboard in 5 seconds...")
    
    # Wait for servers to start
    time.sleep(5)
    
    # Open dashboard in browser
    webbrowser.open("http://localhost:5500")
    
    print("\n[✓] Dashboard opened in browser!")
    print("\nPress Ctrl+C in each terminal to stop components.\n")

if __name__ == "__main__":
    main()