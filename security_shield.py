# security_shield.py - أدوات التشفير والأمان المتقدمة
import base64
import hmac
import hashlib
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class SecurityShield:
    def __init__(self, master_secret: bytes):
        self.master_secret = master_secret
        self._derive_key()
    
    def _derive_key(self, salt: bytes = b'salt_2026'):
        """اشتقاق مفتاح تشفير قوي من كلمة السر الرئيسية"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.master_secret))
        self.cipher = Fernet(key)
    
    def encrypt(self, data: str) -> str:
        """تشفير نص باستخدام AES-256"""
        if not data:
            return ''
        return self.cipher.encrypt(data.encode()).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """فك تشفير نص"""
        if not encrypted_data:
            return ''
        return self.cipher.decrypt(encrypted_data.encode()).decode()
    
    def generate_device_fingerprint(self, client_serial: str) -> str:
        """توليد بصمة فريدة للجهاز"""
        return hmac.new(
            self.master_secret,
            client_serial.encode(),
            hashlib.sha256
        ).hexdigest()
    
    def verify_token(self, token: str, client_serial: str, timestamp: int) -> bool:
        """التحقق من صحة التوكن (لمدة ساعة)"""
        expected = hmac.new(
            self.master_secret,
            f"{client_serial}:{timestamp // 3600}".encode(),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(token, expected)
