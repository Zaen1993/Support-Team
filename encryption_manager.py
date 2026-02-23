#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import base64
import hashlib
import hmac
import secrets
from typing import Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

try:
    import liboqs
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False

class EncryptionManager:
    def __init__(self, master_secret: bytes, salt: bytes, use_pqc: bool = False):
        self.master_secret = master_secret
        self.salt = salt
        self.backend = default_backend()
        self.use_pqc = use_pqc and OQS_AVAILABLE

    def derive_device_key(self, device_id: str) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt + device_id.encode(),
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(self.master_secret)

    def generate_ephemeral_keypair(self) -> Tuple:
        if self.use_pqc:
            kem = liboqs.KeyEncapsulation('Kyber512')
            public_key = kem.generate_keypair()
            return kem, public_key
        else:
            private_key = x25519.X25519PrivateKey.generate()
            public_key = private_key.public_key()
            return private_key, public_key

    def compute_shared_secret(self, private_key, peer_public_bytes: bytes) -> bytes:
        if self.use_pqc:
            return private_key.decap_secret(peer_public_bytes)
        else:
            peer_public = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
            shared = private_key.exchange(peer_public)
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                info=b"session-key",
                backend=self.backend
            )
            return hkdf.derive(shared)

    def derive_session_keys(self, shared_secret: bytes, context: str) -> Tuple[bytes, bytes]:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=self.salt,
            info=context.encode(),
            backend=self.backend
        )
        output = hkdf.derive(shared_secret)
        return output[:32], output[32:]

    def derive_hmac_key(self, enc_key: bytes, device_id: str) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            info=device_id.encode() + b"_hmac",
            backend=self.backend
        )
        return hkdf.derive(enc_key)

    def encrypt_packet(self, key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
        iv = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext

    def decrypt_packet(self, key: bytes, packet: bytes, aad: bytes = b"") -> bytes:
        iv = packet[:12]
        tag = packet[12:28]
        ciphertext = packet[28:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(aad)
        return decryptor.update(ciphertext) + decryptor.finalize()

    def encrypt_stored_key(self, key_material: bytes) -> bytes:
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
        ciphertext = encryptor.update(key_material) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext

    def decrypt_stored_key(self, encrypted_data: bytes) -> bytes:
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

    def sign_hmac(self, key: bytes, message: bytes) -> str:
        h = hmac.new(key, message, hashlib.sha256)
        return h.hexdigest()

    def verify_hmac(self, key: bytes, message: bytes, signature_hex: str) -> bool:
        expected = self.sign_hmac(key, message)
        return hmac.compare_digest(expected, signature_hex)

    def device_fingerprint(self, device_id: str) -> str:
        device_key = self.derive_device_key(device_id)
        return self.sign_hmac(device_key, device_id.encode())
