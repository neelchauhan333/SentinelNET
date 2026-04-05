# backend/database.py
"""
SQLite Database Manager for SentinelNet - THREAD SAFE VERSION
✅ Fixed all threading issues
✅ Safe for concurrent access
✅ Performance indexes added
✅ Logging system integrated
"""

import sqlite3
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
import threading

DB_FILE = Path("backend/sentinelnet.db")

logger = logging.getLogger("sentinelnet")


class SimpleDatabase:
    """Thread-safe database manager"""
    
    def __init__(self):
        self.db_file = str(DB_FILE)
        self.local = threading.local()
        self.setup_tables()
    
    def get_connection(self):
        """Get thread-local connection"""
        if not hasattr(self.local, 'conn'):
            self.local.conn = sqlite3.connect(
                self.db_file,
                check_same_thread=False,
                timeout=10.0
            )
            self.local.conn.row_factory = sqlite3.Row
        return self.local.conn
    
    def setup_tables(self):
        """Create tables and performance indexes"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Devices table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                ip_address TEXT,
                mac_address TEXT,
                hostname TEXT,
                device_type TEXT,
                vendor TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                blocked_status INTEGER DEFAULT 0,
                risk_score INTEGER DEFAULT 0
            )
        """)
        
        # Events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                device_id TEXT,
                event_type TEXT,
                event_time TEXT,
                event_data TEXT,
                severity TEXT DEFAULT 'LOW'
            )
        """)
        
        # Risk history
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS risk_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT,
                timestamp TEXT,
                risk_score INTEGER
            )
        """)

        # ── Performance indexes ──────────────────────────────────
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_device_id ON events(device_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_event_time ON events(event_time)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_risk_history_device ON risk_history(device_id)")
        
        conn.commit()
        conn.close()
        logger.info("Database initialized with indexes")
        print("[✓] Database initialized")
    
    # ========== DEVICE OPERATIONS ==========
    
    def save_device(self, device: Dict):
        """Save or update device"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "SELECT first_seen FROM devices WHERE device_id = ?",
                (device['device_id'],)
            )
            existing = cursor.fetchone()
            
            if existing:
                cursor.execute("""
                    UPDATE devices SET 
                        ip_address = ?,
                        mac_address = ?,
                        hostname = ?,
                        device_type = ?,
                        vendor = ?,
                        last_seen = ?
                    WHERE device_id = ?
                """, (
                    device.get('ip_address'),
                    device.get('mac_address'),
                    device.get('hostname'),
                    device.get('device_type'),
                    device.get('vendor'),
                    device.get('last_seen', str(datetime.now())),
                    device['device_id']
                ))
            else:
                cursor.execute("""
                    INSERT INTO devices 
                    (device_id, ip_address, mac_address, hostname, 
                     device_type, vendor, first_seen, last_seen, 
                     blocked_status, risk_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    device['device_id'],
                    device.get('ip_address'),
                    device.get('mac_address'),
                    device.get('hostname'),
                    device.get('device_type'),
                    device.get('vendor'),
                    str(datetime.now()),
                    device.get('last_seen', str(datetime.now())),
                    0,
                    0
                ))
            
            conn.commit()
        except Exception as e:
            logger.error(f"save_device error: {str(e)}")
            conn.rollback()
    
    def get_all_devices(self) -> List[Dict]:
        """Get all devices - THREAD SAFE"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC")
            rows = cursor.fetchall()
            
            devices = []
            for row in rows:
                device = dict(row)
                device['blocked_status'] = bool(device.get('blocked_status', 0))
                device['risk_reasons'] = []
                devices.append(device)
            
            return devices
        except Exception as e:
            logger.error(f"get_all_devices error: {str(e)}")
            return []
    
    def get_device(self, device_id: str) -> Optional[Dict]:
        """Get single device"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,))
            row = cursor.fetchone()
            
            if row:
                device = dict(row)
                device['blocked_status'] = bool(device.get('blocked_status', 0))
                return device
            return None
        except Exception as e:
            logger.error(f"get_device error: {str(e)}")
            return None
    
    def update_device_risk(self, device_id: str, risk_score: int):
        """Update risk score"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "UPDATE devices SET risk_score = ? WHERE device_id = ?",
                (risk_score, device_id)
            )
            
            cursor.execute("""
                INSERT INTO risk_history (device_id, timestamp, risk_score)
                VALUES (?, ?, ?)
            """, (device_id, str(datetime.now()), risk_score))
            
            conn.commit()
        except Exception as e:
            logger.error(f"update_device_risk error: {str(e)}")
            conn.rollback()
    
    def block_device(self, device_id: str):
        """Block device"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "UPDATE devices SET blocked_status = 1 WHERE device_id = ?",
                (device_id,)
            )
            conn.commit()
        except Exception as e:
            logger.error(f"block_device error: {str(e)}")
            conn.rollback()
    
    def unblock_device(self, device_id: str):
        """Unblock device"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "UPDATE devices SET blocked_status = 0 WHERE device_id = ?",
                (device_id,)
            )
            conn.commit()
        except Exception as e:
            logger.error(f"unblock_device error: {str(e)}")
            conn.rollback()
    
    # ========== EVENT OPERATIONS ==========
    
    def save_event(self, event: Dict):
        """Save event - THREAD SAFE"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO events 
                (event_id, device_id, event_type, event_time, event_data, severity)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                event['event_id'],
                event['device_id'],
                event['event_type'],
                event.get('event_time', str(datetime.now())),
                json.dumps(event.get('event_data', {})),
                event.get('severity', 'LOW')
            ))
            
            conn.commit()
        except Exception as e:
            logger.error(f"save_event error: {str(e)}")
            conn.rollback()
    
    def get_all_events(self, limit: int = 200) -> List[Dict]:
        """Get recent events - THREAD SAFE"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "SELECT * FROM events ORDER BY event_time DESC LIMIT ?",
                (limit,)
            )
            
            events = []
            for row in cursor.fetchall():
                event = dict(row)
                event_data_str = event.get('event_data')
                if event_data_str:
                    try:
                        event['event_data'] = json.loads(event_data_str)
                    except Exception:
                        event['event_data'] = {}
                else:
                    event['event_data'] = {}
                events.append(event)
            
            return events
        except Exception as e:
            logger.error(f"get_all_events error: {str(e)}")
            return []
    
    def get_device_events(self, device_id: str) -> List[Dict]:
        """Get events for device"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT * FROM events 
                WHERE device_id = ? 
                ORDER BY event_time DESC
            """, (device_id,))
            
            events = []
            for row in cursor.fetchall():
                event = dict(row)
                event_data_str = event.get('event_data')
                if event_data_str:
                    try:
                        event['event_data'] = json.loads(event_data_str)
                    except Exception:
                        event['event_data'] = {}
                else:
                    event['event_data'] = {}
                events.append(event)
            
            return events
        except Exception as e:
            logger.error(f"get_device_events error: {str(e)}")
            return []
    
    # ========== RISK HISTORY ==========
    
    def get_risk_history(self, device_id: str, limit: int = 50) -> List[Dict]:
        """Get risk history"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT timestamp, risk_score 
                FROM risk_history 
                WHERE device_id = ? 
                ORDER BY timestamp ASC 
                LIMIT ?
            """, (device_id, limit))
            
            return [
                {'time': row[0], 'score': row[1]}
                for row in cursor.fetchall()
            ]
        except Exception as e:
            logger.error(f"get_risk_history error: {str(e)}")
            return []
    
    # ========== STATISTICS ==========
    
    def get_stats(self) -> Dict:
        """Get dashboard statistics"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT COUNT(*) FROM devices WHERE risk_score >= 70")
            high = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM devices WHERE risk_score >= 40 AND risk_score < 70")
            suspicious = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM devices WHERE risk_score < 40")
            safe = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM devices")
            total = cursor.fetchone()[0]
            
            return {
                'safe': safe,
                'suspicious': suspicious,
                'high': high,
                'total': total
            }
        except Exception as e:
            logger.error(f"get_stats error: {str(e)}")
            return {'safe': 0, 'suspicious': 0, 'high': 0, 'total': 0}


# Global instance
db = SimpleDatabase()