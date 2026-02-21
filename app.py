import os
from flask import Flask, jsonify, request
from supabase import create_client, Client

app = Flask(__name__)

# نستخدم الـ IP المباشر لخدمات Supabase (عبر Cloudflare) لتجاوز خطأ DNS
# ملاحظة: إذا تغير الـ IP مستقبلاً سنعيد الرابط النصي، لكن حالياً هذا هو الحل للاتصال
URL = "https://104.21.50.231" 
KEY = "sb_publishable_bhDsYAE3AkjETs8UFGyK_w_p7VyMMsP"
ORIGINAL_HOST = "ybhticzotyyvyuxkfkwv.supabase.co"

@app.route('/')
def home():
    return jsonify({"status": "active", "message": "DNS Bypass Active"})

@app.route('/test-db')
def test_db():
    try:
        # نقوم بإنشاء العميل مع إضافة الـ Host الأصلي في الـ Headers ليعرف Supabase أن الطلب له
        headers = {"Host": ORIGINAL_HOST}
        client = create_client(URL, KEY, options={"headers": headers})
        
        response = client.table('victims').select("*").limit(1).execute()
        return jsonify({
            "success": True, 
            "data": response.data,
            "message": "Connected via IP Direct"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error_detail": str(e),
            "hint": "Check if your Supabase Project is PAUSED in their dashboard"
        })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
