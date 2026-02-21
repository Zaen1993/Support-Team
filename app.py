import os
import socket
from flask import Flask, jsonify, request
from supabase import create_client, Client

app = Flask(__name__)

# Direct Configuration
# We use the direct URL. If DNS fails, we attempt to resolve it manually.
URL = "https://ybhticzotyyvyuxkfkwv.supabase.co"
KEY = "sb_publishable_bhDsYAE3AkjETs8UFGyK_w_p7VyMMsP"

try:
    supabase: Client = create_client(URL, KEY)
except Exception as e:
    print(f"Initialization Error: {e}")

@app.route('/')
def home():
    return jsonify({
        "status": "active",
        "message": "System is online. DNS Debugging active."
    })

@app.route('/test-db')
def test_db():
    try:
        # Check if the host is reachable
        host = "ybhticzotyyvyuxkfkwv.supabase.co"
        ip = socket.gethostbyname(host)
        
        response = supabase.table('victims').select("*").limit(1).execute()
        return jsonify({
            "success": True,
            "ip_resolved": ip,
            "message": "Connection Established!"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error_type": "Network/DNS Issue",
            "details": str(e)
        })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
