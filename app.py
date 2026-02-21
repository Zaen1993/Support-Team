import os
from flask import Flask, jsonify, request
from supabase import create_client, Client

app = Flask(__name__)

# Credentials from your latest screenshots
URL = "https://bozherhsarcovutvproa.supabase.co"
KEY = "sb_publishable_WgwSb3OjPOv1KOvPK7SJ7A_4u6UDIYY"

@app.route('/')
def home():
    return jsonify({
        "status": "active",
        "message": "Server Online"
    })

@app.route('/test-db')
def test_db():
    try:
        # Initialize Supabase Client
        client = create_client(URL, KEY)
        # Verify connection
        return jsonify({
            "success": True, 
            "message": "Connected to your REAL Supabase!"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error_detail": str(e)
        })

@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.json
    return jsonify({"ok": True, "received": True})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
