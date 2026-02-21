import os
from flask import Flask, jsonify, request
from supabase import create_client, Client
import httpx

app = Flask(__name__)

# Configuration
SUPABASE_URL = "https://ybhticzotyyvyuxkfkwv.supabase.co"
SUPABASE_KEY = "sb_publishable_bhDsYAE3AkjETs8UFGyK_w_p7VyMMsP"

# Initialize Client with custom HTTPX configuration for stability
try:
    supabase: Client = create_client(
        SUPABASE_URL, 
        SUPABASE_KEY,
        options={"postgrest_client_timeout": 20}
    )
except Exception as e:
    supabase = None

@app.route('/')
def home():
    return jsonify({
        "status": "active",
        "message": "System Online"
    })

@app.route('/test-db')
def test_db():
    if not supabase:
        return jsonify({"success": False, "error": "Client not initialized"})
    
    try:
        # Check connection by fetching 1 row from victims table
        response = supabase.table('victims').select("*").limit(1).execute()
        return jsonify({
            "success": True,
            "data": response.data,
            "message": "Connected"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        })

@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.json
    if data:
        print(f"Payload: {data}")
    return jsonify({"ok": True})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
