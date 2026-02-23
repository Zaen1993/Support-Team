#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
crypto_utils.py – تشفير متقدم لكل جهاز مع حماية من التحليل
يدعم:
- ECDH (X25519) لتبادل المفاتيح
- AES-256-GCM لتشفير البيانات
- PBKDF2 لاشتقاق المفاتيح
- HKDF لاستخلاص مفاتيح الجلسة
- تخزين آمن للمفاتيح في قاعدة البيانات
- (اختياري) دعم Kyber للحماية الكمومية إذا كانت liboqs متوفرة
"""

import os
import base64
import hashlib
import hmac
import secrets
import logging
from typing import Tuple, Optional

# cryptography هي المكتبة الموصى بها للتشفير في Python
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# محاولة استيراد liboqs للتشفير ما بعد الكم (اختياري)
try:
    import liboqs
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False
    logging.info("liboqs not installed, quantum-resistant encryption disabled.")


class CryptoManager:
    """
    مدير التشفير المسؤول عن جميع العمليات التشفيرية الحساسة.
    يعتمد على مفتاح رئيسي واحد (master_secret) يتم تخزينه في متغير البيئة.
    """

    def __init__(self, master_secret: bytes, salt: bytes):
        """
        :param master_secret: المفتاح الرئيسي للنظام (32 بايت على الأقل، يفضل 32)
        :param salt: قيمة ملح ثابتة (يفضل 16 بايت)
        """
        self.master_secret = master_secret
        self.salt = salt
        self.backend = default_backend()
        self.use_pqc = OQS_AVAILABLE and os.environ.get('ENABLE_PQC', 'false').lower() == 'true'

    # ------------------------------------------------------------
    # 1. اشتقاق مفتاح خاص بجهاز معين (Device‑Specific Key)
    # ------------------------------------------------------------
    def derive_device_key(self, device_id: str) -> bytes:
        """
        يشتق مفتاحاً فريداً للجهاز باستخدام PBKDF2 مع 100,000 تكرار.
        المفتاح الناتج يستخدم لتوقيع HMAC ولمشتقات أخرى.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt + device_id.encode(),
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(self.master_secret)

    # ------------------------------------------------------------
    # 2. إنشاء زوج مفاتيح مؤقت (Ephemeral Keypair) لتبادل ECDH
    # ------------------------------------------------------------
    def generate_ephemeral_keypair(self):
        """
        ينشئ زوج مفاتيح مؤقت باستخدام X25519.
        إذا تم تفعيل PQC، يستخدم Kyber بدلاً من ذلك (يتطلب liboqs).
        :return: (private_key, public_key)
                 private_key يمكن أن يكون كائن X25519PrivateKey أو كائن KeyEncapsulation من liboqs
                 public_key هو بايتات المفتاح العمومي (قد يكون bytes مباشرة)
        """
        if self.use_pqc and OQS_AVAILABLE:
            # استخدام Kyber (مقاوم للكم)
            kem = liboqs.KeyEncapsulation('Kyber512')
            public_key = kem.generate_keypair()  # returns bytes
            # نعيد kem نفسه لاستخدامه في compute_shared_secret (سيحتاج إلى decapsulate)
            return kem, public_key
        else:
            private_key = x25519.X25519PrivateKey.generate()
            public_key = private_key.public_key()
            return private_key, public_key

    # ------------------------------------------------------------
    # 3. حساب المفتاح المشترك (Shared Secret)
    # ------------------------------------------------------------
    def compute_shared_secret(self, private_key, peer_public_bytes: bytes) -> bytes:
        """
        يحسب المفتاح المشترك باستخدام X25519 (أو Kyber).
        ثم يطبق HKDF لاشتقاق مفتاح جلسة نهائي (32 بايت).
        """
        if self.use_pqc and OQS_AVAILABLE:
            # هنا نتوقع أن private_key هو كائن KeyEncapsulation من liboqs
            shared_secret = private_key.decap_secret(peer_public_bytes)
        else:
            peer_public = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
            shared_secret = private_key.exchange(peer_public)

        # اشتقاق مفتاح جلسة نهائي عبر HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            info=b"session-key",
            backend=self.backend
        )
        return hkdf.derive(shared_secret)

    # ------------------------------------------------------------
    # 4. تشفير حزمة بيانات باستخدام AES-GCM (مع بيانات إضافية)
    # ------------------------------------------------------------
    def encrypt_packet(self, key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
        """
        تشفير AES-GCM مع مفتاح 256 بت.
        الناتج: [12 بايت IV] + [16 بايت Tag] + [النص المشفر].
        """
        iv = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext

    # ------------------------------------------------------------
    # 5. فك تشفير حزمة بيانات (AES-GCM)
    # ------------------------------------------------------------
    def decrypt_packet(self, key: bytes, packet: bytes, aad: bytes = b"") -> bytes:
        """
        فك تشفير حزمة بيانات مشفرة بـ AES-GCM.
        تفترض أن الحزمة تبدأ بـ 12 بايت IV ثم 16 بايت Tag ثم النص المشفر.
        """
        iv = packet[:12]
        tag = packet[12:28]
        ciphertext = packet[28:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(aad)
        return decryptor.update(ciphertext) + decryptor.finalize()

    # ------------------------------------------------------------
    # 6. تشفير مفتاح لتخزينه في قاعدة البيانات (باستخدام المفتاح الرئيسي)
    # ------------------------------------------------------------
    def encrypt_stored_key(self, key_material: bytes) -> bytes:
        """
        تشفير مادة المفاتيح (مثل المفتاح المشترك) لتخزينها بشكل دائم.
        يستخدم المفتاح الرئيسي (master_secret) كمفتاح تغليف بعد اشتقاقه عبر HKDF.
        """
        # اشتقاق مفتاح تغليف من الماستر سيكرت (مع info منفصل)
        wrapping_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            info=b"key-wrapping",
            backend=self.backend
        ).derive(self.master_secret)

        iv = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(wrapping_key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        # لا توجد بيانات إضافية لتخزين المفاتيح
        ciphertext = encryptor.update(key_material) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext

    # ------------------------------------------------------------
    # 7. فك تشفير مفتاح مخزن
    # ------------------------------------------------------------
    def decrypt_stored_key(self, encrypted_data: bytes) -> bytes:
        """
        فك تشفير مفتاح كان قد شُفر بـ encrypt_stored_key.
        """
        wrapping_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            info=b"key-wrapping",
            backend=self.backend
        ).derive(self.master_secret)

        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]
        cipher = Cipher(algorithms.AES(wrapping_key), modes.GCM(iv, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    # ------------------------------------------------------------
    # 8. توقيع HMAC (يستخدم للمصادقة)
    # ------------------------------------------------------------
    def sign_hmac(self, key: bytes, message: bytes) -> str:
        """
        يحسب HMAC-SHA256 باستخدام المفتاح المعطى.
        يعيد النتيجة كسلسلة hex (64 حرفاً).
        """
        h = crypto_hmac.HMAC(key, hashes.SHA256(), backend=self.backend)
        h.update(message)
        return h.finalize().hex()

    # ------------------------------------------------------------
    # 9. التحقق من توقيع HMAC
    # ------------------------------------------------------------
    def verify_hmac(self, key: bytes, message: bytes, signature_hex: str) -> bool:
        """
        يتحقق من صحة توقيع HMAC.
        """
        h = crypto_hmac.HMAC(key, hashes.SHA256(), backend=self.backend)
        h.update(message)
        try:
            h.verify(bytes.fromhex(signature_hex))
            return True
        except Exception:
            return False

    # ------------------------------------------------------------
    # 10. دوال مساعدة للتشفير السريع للنصوص الصغيرة (اختياري)
    # ------------------------------------------------------------
    def quick_encrypt(self, key: bytes, plaintext: str) -> str:
        """تشفير نص قصير وإرجاعه كـ base64."""
        encrypted = self.encrypt_packet(key, plaintext.encode())
        return base64.b64encode(encrypted).decode()

    def quick_decrypt(self, key: bytes, encrypted_b64: str) -> str:
        """فك تشفير نص مشفر سابقاً بـ quick_encrypt."""
        data = base64.b64decode(encrypted_b64)
        decrypted = self.decrypt_packet(key, data)
        return decrypted.decode()

    # ------------------------------------------------------------
    # 11. توليد بصمة فريدة للجهاز (للاستخدام في المصادقة)
    # ------------------------------------------------------------
    def device_fingerprint(self, device_id: str) -> str:
        """
        ينشئ بصمة للجهاز باستخدام HMAC من المفتاح الرئيسي.
        يمكن استخدامها للتحقق من أن الجهاز معروف للنظام.
        """
        device_key = self.derive_device_key(device_id)
        return self.sign_hmac(device_key, device_id.encode())        )
        return hkdf.derive(shared_secret)

    # ------------------------------------------------------------
    # 4. تشفير حزمة بيانات باستخدام AES-GCM (مع بيانات إضافية)
    # ------------------------------------------------------------
    def encrypt_packet(self, key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
        """
        تشفير AES-GCM مع مفتاح 256 بت.
        الناتج: [12 بايت IV] + [16 بايت Tag] + [النص المشفر].
        """
        iv = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext

    # ------------------------------------------------------------
    # 5. فك تشفير حزمة بيانات (AES-GCM)
    # ------------------------------------------------------------
    def decrypt_packet(self, key: bytes, packet: bytes, aad: bytes = b"") -> bytes:
        """
        فك تشفير حزمة بيانات مشفرة بـ AES-GCM.
        تفترض أن الحزمة تبدأ بـ 12 بايت IV ثم 16 بايت Tag ثم النص المشفر.
        """
        iv = packet[:12]
        tag = packet[12:28]
        ciphertext = packet[28:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(aad)
        return decryptor.update(ciphertext) + decryptor.finalize()

    # ------------------------------------------------------------
    # 6. توقيع HMAC (يستخدم للمصادقة)
    # ------------------------------------------------------------
    def sign_hmac(self, device_key: bytes, message: bytes) -> str:
        """
        يحسب HMAC-SHA256 باستخدام مفتاح الجهاز.
        يعيد النتيجة كسلسلة hex (64 حرفاً).
        """
        return hmac.new(device_key, message, hashlib.sha256).hexdigest()

    # ------------------------------------------------------------
    # 7. دوال مساعدة للتشفير السريع للنصوص الصغيرة (اختياري)
    # ------------------------------------------------------------
    def quick_encrypt(self, key: bytes, plaintext: str) -> str:
        """تشفير نص قصير وإرجاعه كـ base64."""
        encrypted = self.encrypt_packet(key, plaintext.encode())
        return base64.b64encode(encrypted).decode()

    def quick_decrypt(self, key: bytes, encrypted_b64: str) -> str:
        """فك تشفير نص مشفر سابقاً بـ quick_encrypt."""
        data = base64.b64decode(encrypted_b64)
        decrypted = self.decrypt_packet(key, data)
        return decrypted.decode()

    # ------------------------------------------------------------
    # 8. توليد بصمة فريدة للجهاز (للاستخدام في المصادقة)
    # ------------------------------------------------------------
    def device_fingerprint(self, device_id: str) -> str:
        """
        ينشئ بصمة للجهاز باستخدام HMAC من المفتاح الرئيسي.
        يمكن استخدامها للتحقق من أن الجهاز معروف للنظام.
        """
        device_key = self.derive_device_key(device_id)
        return self.sign_hmac(device_key, device_id.encode())
