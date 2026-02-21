import os
from flask import Flask, jsonify, request
from supabase import create_client, Client

app = Flask(__name__)

# ضع الروابط الخاصة بك من صفحة Settings -> API في Supabase
URL = "https://bozherhsarcovutvproa.supabase.co" # تأكد أنه الرابط الصحيح من لقطة شاشتك
KEY = "ضع_هنا_مفتاح_anon_key_الخاص_بك"

@app.route('/')
def home():
    return jsonify({"status": "active", "message": "Server is Online"})

@app.route('/test-db')
def test_db():
    try:
        client = create_client(URL, KEY)
        # سيحاول جلب البيانات من جدول victims
        response = client.table('victims').select("*").limit(1).execute()
        return jsonify({
            "success": True, 
            "message": "Successfully connected to your REAL Supabase!"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error_detail": str(e)
        })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
