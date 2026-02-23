# security_shield.py
import base64
import hmac
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class SecurityShield:
    def __init__(self, master_secret: bytes):
        self.master_secret = master_secret
        self._derive_key()

    def _derive_key(self, salt: bytes = b'salt_2026'):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.master_secret))
        self.cipher = Fernet(key)

    def encrypt(self, data: str) -> str:
        return self.cipher.encrypt(data.encode()).decode() if data else ''

    def decrypt(self, data: str) -> str:
        return self.cipher.decrypt(data.encode()).decode() if data else ''
