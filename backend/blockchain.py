# backend/blockchain.py
import hashlib
import json
from datetime import datetime
from pathlib import Path

CHAIN_FILE = Path("backend/blockchain.json")

def ensure_chain():
    if not CHAIN_FILE.exists() or CHAIN_FILE.read_text().strip() == "":
        create_genesis_block()

def create_genesis_block():
    genesis = {
        "index": 0,
        "timestamp": str(datetime.now()),
        "data": "Genesis Block",
        "previous_hash": "0",
    }
    genesis["current_hash"] = hash_block(genesis)
    CHAIN_FILE.write_text(json.dumps([genesis], indent=4))
    return genesis

def hash_block(block):
    block_string = json.dumps(block, sort_keys=True).encode()
    return hashlib.sha256(block_string).hexdigest()

def add_block(data):
    ensure_chain()
    chain = json.loads(CHAIN_FILE.read_text())
    last_block = chain[-1]
    new_block = {
        "index": len(chain),
        "timestamp": str(datetime.now()),
        "data": data,
        "previous_hash": last_block["current_hash"]
    }
    new_block["current_hash"] = hash_block(new_block)
    chain.append(new_block)
    CHAIN_FILE.write_text(json.dumps(chain, indent=4))
    return new_block
