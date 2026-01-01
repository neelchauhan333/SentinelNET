from pydantic import BaseModel

class Device(BaseModel):
    device_id: str
    ip_address: str
    mac_address: str
    hostname: str
    last_seen: str
    blocked_status: bool = False

class Event(BaseModel):
    event_id: str
    device_id: str
    event_type: str
    event_time: str
    event_data: dict
