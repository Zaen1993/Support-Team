# core_service_monitor.py
import os
import hmac
import hashlib
from flask import Flask, jsonify, request
from supabase import create_client
from security_shield import SecurityShield

app = Flask(__name__)

# الإعدادات من متغيرات البيئة
SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
MASTER_SECRET = os.environ.get('MASTER_SECRET', 'default-secret-key').encode()
ACCESS_KEY = os.environ.get('ACCESS_KEY', 'default-access-key')

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
shield = SecurityShield(MASTER_SECRET)

# التحقق من المصادقة
def authenticate_request():
    auth = request.headers.get('X-Service-Auth')
    return auth and hmac.compare_digest(auth, ACCESS_KEY)

@app.before_request
def before_request():
    if request.path != '/' and not authenticate_request():
        return jsonify({"error": "Not Found"}), 404

@app.route('/')
def home():
    return jsonify({
        "company": "Acme Solutions",
        "service": "POS Device Management API",
        "version": "2.3.1"
    })

@app.route('/api/register-client', methods=['POST'])
def register_client():
    data = request.json
    client_serial = data.get('client_serial')
    if not client_serial:
        return jsonify({"error": "missing client_serial"}), 400

    supabase.table('pos_clients').upsert({
        'client_serial': client_serial,
        'last_ping': 'now()',
        'operational_status': 'online'
    }).execute()
    return jsonify({"status": "registered"})

@app.route('/api/poll/<client_serial>', methods=['GET'])
def poll_requests(client_serial):
    requests = supabase.table('service_requests') \
        .select('*') \
        .eq('target_client', client_serial) \
        .eq('ticket_status', 'open') \
        .execute()
    return jsonify(requests.data)

@app.route('/api/result', methods=['POST'])
def submit_result():
    data = request.json
    ticket_id = data.get('ticket_id')
    resolution = data.get('resolution_log')
    if not ticket_id or not resolution:
        return jsonify({"error": "missing data"}), 400

    encrypted = shield.encrypt(resolution)
    supabase.table('service_requests') \
        .update({'resolution_log': encrypted, 'ticket_status': 'closed'}) \
        .eq('ticket_id', ticket_id) \
        .execute()
    return jsonify({"status": "received"})

@app.route('/api/log-error', methods=['POST'])
def log_error():
    data = request.json
    payload = data.get('error_payload')
    if payload:
        encrypted = shield.encrypt(payload)
        supabase.table('error_logs').insert({'error_payload': encrypted}).execute()
    return jsonify({"status": "logged"})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)    for req in requests.data:
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
