import os
from flask import Flask, jsonify, request
from supabase import create_client, Client

app = Flask(__name__)

# قراءة متغيرات البيئة من Render
SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')

# إنشاء عميل Supabase
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

@app.route('/')
def home():
    return jsonify({
        "status": "active",
        "message": "Flask server with Supabase is running!"
    })

@app.route('/test-db')
def test_db():
    try:
        # محاولة جلب البيانات من جدول victims
        response = supabase.table('victims').select("*").limit(1).execute()
        return jsonify({
            "success": True,
            "data": response.data,
            "message": "Connected to Supabase!"
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
    app.run()
