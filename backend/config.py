"""
SentinelNet Configuration
Centralised settings for the entire system.
"""

# ── API Security ──────────────────────────────────────────────
API_KEY = "sentinel123"          # Change before production

# ── Risk Engine ───────────────────────────────────────────────
RISK_THRESHOLD    = 70           # Auto-block threshold (0-100)
RISK_SUSPICIOUS   = 40           # Suspicious zone lower bound

# ── Scanner ───────────────────────────────────────────────────
SCAN_INTERVAL     = 300          # Seconds between auto-scans

# ── Backend ───────────────────────────────────────────────────
BACKEND_URL       = "http://127.0.0.1:8000"

# ── Logging ───────────────────────────────────────────────────
LOG_FILE          = "sentinelnet.log"
LOG_LEVEL         = "INFO"       # DEBUG | INFO | WARNING | ERROR