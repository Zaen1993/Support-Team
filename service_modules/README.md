# POS Device Management System

نظام إدارة ومراقبة أجهزة نقاط البيع عن بعد. يتيح:
- تسجيل الأجهزة
- إرسال طلبات الصيانة
- استقبال تقارير الأخطاء

## متغيرات البيئة المطلوبة
- `SUPABASE_URL`: رابط مشروع Supabase
- `SUPABASE_KEY`: المفتاح العام (anon key)
- `MASTER_SECRET`: كلمة سر رئيسية للتشفير
- `ACCESS_KEY`: مفتاح وصول للـ API

## التشغيل المحلي
```bash
pip install -r requirements.txt
python core_service_monitor.py
