"""
CRYPTOGRAPHY MODULE - SHA-256 Hashing for Log Integrity
Week 8: Hashing & Digital Signatures
"""

import hashlib
import json
from datetime import datetime

class CryptoUtils:
    def __init__(self):
        self.hash_algorithm = "SHA-256"
    
    def calculate_hash(self, data):
        """Calculate SHA-256 hash for integrity verification"""
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True)
        elif not isinstance(data, str):
            data = str(data)
        return hashlib.sha256(data.encode()).hexdigest()
    
    def verify_integrity(self, data, original_hash):
        """Verify data hasn't been tampered"""
        return self.calculate_hash(data) == original_hash
    
    def hash_file(self, filepath):
        """Calculate SHA-256 hash of a file"""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for block in iter(lambda: f.read(4096), b""):
                    sha256.update(block)
            return sha256.hexdigest()
        except:
            return None

if __name__ == "__main__":
    crypto = CryptoUtils()
    test = {"message": "SIEM Log Entry", "timestamp": datetime.now().isoformat()}
    hash_val = crypto.calculate_hash(test)
    print(f"🔐 SHA-256 Hash: {hash_val[:32]}...")
    print(f"✅ Integrity Verified: {crypto.verify_integrity(test, hash_val)}")