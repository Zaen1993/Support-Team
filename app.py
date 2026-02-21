from flask import Flask, jsonify, request
import os

# إنشاء تطبيق Flask
app = Flask(__name__)

# مسار تجريبي للتأكد من أن الخادم شغال
@app.route('/')
def home():
    return jsonify({
        "status": "active",
        "message": "Flask server is running on Render!"
    })

# مسار لاستقبال Webhook من تليجرام (سنفعلها لاحقاً)
@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.json
    # هنا هنستقبل الأوامر من تليجرام
    print("Received:", data)
    return jsonify({"ok": True})

# هذا السطر ضروري لتشغيل التطبيق محلياً
if __name__ == '__main__':
    app.run(debug=True, port=5000)