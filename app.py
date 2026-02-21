import os
from flask import Flask, jsonify, request
from supabase import create_client, Client

app = Flask(__name__)

# Configuration
URL = "https://ybhticzotyyvyuxkfkwv.supabase.co"
KEY = "sb_publishable_bhDsYAE3AkjETs8UFGyK_w_p7VyMMsP"

@app.route('/')
def home():
    return jsonify({
        "status": "active",
        "message": "System Online"
    })

@app.route('/test-db')
def test_db():
    try:
        # Initialize inside the route to capture the exact error
        client = create_client(URL, KEY)
        response = client.table('victims').select("*").limit(1).execute()
        return jsonify({
            "success": True,
            "data": response.data,
            "message": "Connected"
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
