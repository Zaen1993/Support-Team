import os
from flask import Flask, jsonify, request
from supabase import create_client, Client

app = Flask(__name__)

# Direct Configuration to bypass DNS/Environment issues
SUPABASE_URL = "https://ybhticzotyyvyuxkfkwv.supabase.co"
SUPABASE_KEY = "sb_publishable_bhDsYAE3AkjETs8UFGyK_w_p7VyMMsP"

# Initialize Supabase Client
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
        # Fetching data from 'victims' table
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
    print("Received:", data)
    return jsonify({"ok": True})

if __name__ == '__main__':
    # Bind to PORT provided by Render
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
