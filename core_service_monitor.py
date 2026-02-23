# core_service_monitor.py - بوابة إدارة خدمات نقاط البيع
# هذا النظام مخصص لمراقبة أجهزة نقاط البيع عن بعد وإدارة طلبات الصيانة.
import os
import time
import base64
import hmac
import hashlib
from flask import Flask, jsonify, request, abort
from supabase import create_client
from security_shield import SecurityShield

app = Flask(__name__)

# -------------------- الإعدادات الأساسية (من متغيرات البيئة) --------------------
SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
MASTER_SECRET = os.environ.get('MASTER_SECRET', 'default-secret-key').encode()
ACCESS_KEY = os.environ.get('ACCESS_KEY', 'default-access-key')

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("Missing Supabase credentials")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
shield = SecurityShield(MASTER_SECRET)

# -------------------- المصادقة المسبقة (Pre-authentication) --------------------
def authenticate_request():
    """التحقق من وجود مفتاح الوصول الصحيح في الـ Header"""
    auth_header = request.headers.get('X-Service-Auth')
    if not auth_header or not hmac.compare_digest(auth_header, ACCESS_KEY):
        # رد وهمي: نعيد صفحة 404 عادية بدلاً من رفض صريح
        return False
    return True

@app.before_request
def before_request():
    """تنفيذ المصادقة قبل كل طلب (ما عدا الصفحة الرئيسية)"""
    if request.path == '/':
        return
    if not authenticate_request():
        # إعادة توجيه وهمي: صفحة خطأ 404 عادية
        return jsonify({"error": "Not Found"}), 404

# -------------------- نقاط النهاية (Endpoints) --------------------
@app.route('/')
def home():
    """الصفحة الرئيسية - شركة وهمية"""
    return jsonify({
        "company": "Acme Solutions",
        "service": "POS Device Management API",
        "version": "2.3.1",
        "status": "operational"
    })

@app.route('/api/register-client', methods=['POST'])
def register_client():
    """تسجيل جهاز جديد (نقطة بيع) في النظام"""
    data = request.json
    client_serial = data.get('client_serial')
    hardware_uuid = data.get('hardware_uuid', '')

    if not client_serial:
        return jsonify({"error": "missing client_serial"}), 400

    # تشفير بعض الحقول قبل التخزين (اختياري)
    encrypted_uuid = shield.encrypt(hardware_uuid) if hardware_uuid else ''

    # إدراج أو تحديث
    result = supabase.table('pos_clients').upsert({
        'client_serial': client_serial,
        'hardware_uuid': encrypted_uuid,
        'last_ping': 'now()',
        'operational_status': 'online'
    }).execute()

    return jsonify({"status": "registered", "client": client_serial})

@app.route('/api/poll/<client_serial>', methods=['GET'])
def poll_requests(client_serial):
    """جلب طلبات الصيانة المعلقة لجهاز معين"""
    # التحقق من وجود الجهاز (اختياري)
    client = supabase.table('pos_clients').select('*').eq('client_serial', client_serial).execute()
    if not client.data:
        return jsonify({"error": "client not found"}), 404

    # جلب الطلبات المعلقة
    requests = supabase.table('service_requests') \
        .select('*') \
        .eq('target_client', client_serial) \
        .eq('ticket_status', 'open') \
        .order('opened_at') \
        .execute()

    # تحديث حالة الطلبات إلى "قيد المعالجة"
    for req in requests.data:
        supabase.table('service_requests') \
            .update({'ticket_status': 'in_progress'}) \
            .eq('ticket_id', req['ticket_id']) \
            .execute()

    # فك تشفير البيانات إذا كانت مشفرة (اختياري)
    for req in requests.data:
        if req.get('resolution_log'):
            # لا نفك هنا لأنها نتائج قد تكون مشفرة
            pass

    return jsonify(requests.data)

@app.route('/api/result', methods=['POST'])
def submit_result():
    """استقبال نتيجة تنفيذ طلب صيانة من الجهاز"""
    data = request.json
    ticket_id = data.get('ticket_id')
    resolution_log = data.get('resolution_log')
    status = data.get('status', 'closed')

    if not ticket_id or not resolution_log:
        return jsonify({"error": "missing data"}), 400

    # تشفير النتيجة قبل التخزين
    encrypted_log = shield.encrypt(resolution_log)

    # تحديث التذكرة
    supabase.table('service_requests') \
        .update({
            'resolution_log': encrypted_log,
            'ticket_status': status,
            'last_updated': 'now()'
        }) \
        .eq('ticket_id', ticket_id) \
        .execute()

    return jsonify({"status": "received"})

@app.route('/api/log-error', methods=['POST'])
def log_error():
    """تسجيل خطأ من جهاز (لأغراض الدعم الفني)"""
    data = request.json
    error_payload = data.get('error_payload')

    if not error_payload:
        return jsonify({"error": "missing payload"}), 400

    # تشفير الخطأ قبل التخزين
    encrypted_payload = shield.encrypt(error_payload)

    supabase.table('error_logs').insert({
        'error_payload': encrypted_payload
    }).execute()

    return jsonify({"status": "logged"})

@app.route('/api/health-check')
def health_check():
    """فحص صحة النظام (لأغراض المراقبة)"""
    try:
        supabase.table('pos_clients').select('entry_id').limit(1).execute()
        return jsonify({"db": "connected", "cache": "ok"})
    except Exception as e:
        return jsonify({"db": "disconnected", "error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
