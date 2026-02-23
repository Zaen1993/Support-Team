#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import base64
import secrets

class AIObfuscator:
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

    def obfuscate_command(self, command: str) -> str:
        noise = random.choice(self.noise_phrases)
        encoded = base64.b64encode(command.encode()).decode()
        return f"{noise} | {encoded}"

    def deobfuscate_command(self, obfuscated: str) -> str:
        try:
            if ' | ' in obfuscated:
                _, data = obfuscated.split(' | ', 1)
                return base64.b64decode(data).decode()
        except Exception:
            pass
        return obfuscated

    def add_traffic_noise(self, data: bytes, min_padding: int = 256, max_padding: int = 768) -> bytes:
        padding_len = secrets.randbelow(max_padding - min_padding) + min_padding
        return len(data).to_bytes(4, 'big') + data + secrets.token_bytes(padding_len)

    def remove_traffic_noise(self, packet: bytes) -> bytes:
        if len(packet) < 4:
            return packet
        real_len = int.from_bytes(packet[:4], 'big')
        if 4 + real_len <= len(packet):
            return packet[4:4+real_len]
        return packet

    def encode_for_channel(self, data: bytes, channel_type: str = 'base64') -> str:
        if channel_type == 'base64':
            return base64.b64encode(data).decode()
        return data.hex()

    def decode_from_channel(self, data_str: str, channel_type: str = 'base64') -> bytes:
        if channel_type == 'base64':
            return base64.b64decode(data_str)
        return bytes.fromhex(data_str)
