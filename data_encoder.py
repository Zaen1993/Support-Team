#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import base64
import secrets

class DataEncoder:
    def __init__(self):
        self.noise_phrases = [
            "system: optimizing cache",
            "background sync completed",
            "checking for updates",
            "maintaining battery health",
            "network scan finished",
            "app data refreshed",
            "notification delivered",
            "wifi state changed",
            "bluetooth connected",
            "location updated"
        ]

    def encode_command(self, command: str) -> str:
        noise = random.choice(self.noise_phrases)
        encoded = base64.b64encode(command.encode()).decode()
        return f"{noise} | {encoded}"

    def decode_command(self, encoded: str) -> str:
        try:
            if ' | ' in encoded:
                _, data = encoded.split(' | ', 1)
                return base64.b64decode(data).decode()
        except Exception:
            pass
        return encoded

    def add_padding(self, data: bytes, min_pad: int = 256, max_pad: int = 768) -> bytes:
        pad_len = secrets.randbelow(max_pad - min_pad) + min_pad
        return len(data).to_bytes(4, 'big') + data + secrets.token_bytes(pad_len)

    def remove_padding(self, packet: bytes) -> bytes:
        if len(packet) < 4:
            return packet
        real_len = int.from_bytes(packet[:4], 'big')
        if 4 + real_len <= len(packet):
            return packet[4:4+real_len]
        return packet

    def to_base64(self, data: bytes) -> str:
        return base64.b64encode(data).decode()

    def from_base64(self, data_str: str) -> bytes:
        return base64.b64decode(data_str)
