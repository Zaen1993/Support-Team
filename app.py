import os
from flask import Flask, jsonify, request
from supabase import create_client, Client

app = Flask(__name__)

# جلب المتغيرات مع تنظيفها من أي فراغات مخفية
SUPABASE_URL = os.environ.get('SUPABASE_URL', '').strip()
SUPABASE_KEY = os.environ.get('SUPABASE_KEY', '').strip()

# إنشاء عميل Supabase فقط إذا كانت المتغيرات موجودة
if SUPABASE_URL and SUPABASE_KEY:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
else:
    print("Error: SUPABASE_URL or SUPABASE_KEY is missing!")

@app.route('/')
def home():
    return jsonify({
        "status": "active",
        "message": "Flask server with Supabase is running!"
    })

@app.route('/test-db')
def test_db():
    try:
        # فحص الاتصال بالجدول
        response = supabase.table('victims').select("*").limit(1).execute()
        return jsonify({
            "success": True,
            "data": response.data,
            "message": "Connected to Supabase successfully!"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        })

@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.json
    print("Received from Telegram:", data)
    return jsonify({"ok": True})

if __name__ == '__main__':
    # الحصول على المنفذ من Render أو استخدام 5000 كافتراضي
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
