#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
crypto_utils.py – مكتبة التشفير المتقدم للنظام النووي
توفر:
- تشفير لكل جهاز باستخدام ECDH + AES-GCM
- اشتقاق المفاتيح عبر PBKDF2
- دعم اختياري لخوارزميات ما بعد الكم (Kyber) إذا كانت liboqs متوفرة
- HMAC للتحقق من سلامة الرسائل
"""

import os
import hmac
import hashlib
import secrets
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# محاولة استيراد مكتبة ما بعد الكم (اختياري)
try:
    import liboqs
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False


class CryptoManager:
    """
    مدير التشفير المسؤول عن جميع العمليات التشفيرية الحساسة.
    يعتمد على مفتاح رئيسي واحد (master_secret) يتم تخزينه في متغير البيئة.
    """

    def __init__(self, master_secret: bytes, salt: bytes):
        """
        :param master_secret: المفتاح الرئيسي للنظام (32 بايت على الأقل)
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
        """
        if self.use_pqc and OQS_AVAILABLE:
            # استخدام Kyber (مقاوم للكم)
            kem = liboqs.KeyEncapsulation('Kyber512')
            public_key = kem.generate_keypair()
            # نعيد كائن Kem نفسه ليتم استخدامه في compute_shared_secret
            # (لاحظ: هذه واجهة مبسطة، في الإنتاج تحتاج معالجة خاصة)
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
        بحساب المفتاح المشترك باستخدام X25519 (أو Kyber).
        ثم يطبق HKDF لاشتقاق مفتاح جلسة نهائي (32 بايت).
        """
        if self.use_pqc and OQS_AVAILABLE:
            # هنا نتوقع أن private_key هو كائن KeyEncapsulation من liboqs
            # والمفتاح العمومي هو bytes عادي (تم استقباله من الطرف الآخر)
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
