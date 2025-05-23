import asyncio
import aiohttp
import json
import re
import logging
from bs4 import BeautifulSoup
import os
import shutil
from datetime import datetime
import pytz
import base64 # <--- برای دیکد کردن Base64
import urllib.parse # <--- برای کار با URL ها

# --- Configuration ---
URLS_FILE = 'urls.txt'
KEYWORDS_FILE = 'keywords.json'
OUTPUT_DIR = 'output_configs'
README_FILE = 'README.md'
REJECTED_LOG_FILE = 'rejected_configs_report.md'
REQUEST_TIMEOUT = 15
CONCURRENT_REQUESTS = 10

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- Protocol Categories (بسیار مهم: این لیست باید دقیقاً با کلیدهای پروتکل در keywords.json شما یکی باشد) ---
PROTOCOL_CATEGORIES = [
    "Vmess", "Vless", "Trojan", "ShadowSocks", "ShadowSocksR",
    "Tuic", "Hysteria2", "WireGuard"
]

# <<<--- تابع اعتبارسنجی ساختاری بسیار دقیق‌تر --->>>
def is_config_valid(config_string_original, min_len=20, max_len=3000, max_overall_percent_char_ratio=0.6, max_specific_percent25_count=10):
    """
    Checks if a config string has a valid structure for its specific protocol.
    Returns (True, None) if valid, or (False, "reason_string") if invalid.
    """
    config_string = config_string_original.strip()
    l = len(config_string)

    if not (min_len <= l <= max_len):
        return False, f"طول نامعتبر ({l}). مورد انتظار: {min_len}-{max_len}"

    # این دو فیلتر برای موارد بسیار شدید کدگذاری هستند
    if l > 70 and (config_string.count('%') / l) > max_overall_percent_char_ratio : # اگر بیش از 60% رشته % بود
        return False, f"تعداد بسیار زیاد کاراکتر % ({config_string.count('%')})"
    if config_string.count('%25') > max_specific_percent25_count: # اگر بیش از 10 بار %25 تکرار شد
        return False, f"تعداد زیاد تکرار '%25' ({config_string.count('%25')})"

    proto_name_key = None
    proto_prefix_val = None
    for p_key in PROTOCOL_CATEGORIES:
        if config_string.lower().startswith(p_key.lower() + "://"):
            proto_name_key = p_key
            proto_prefix_val = p_key.lower()
            break
    if not proto_prefix_val:
        return False, "پیشوند پروتکل معتبر یافت نشد"

    payload = config_string.split("://", 1)[1]
    main_payload = payload.split("#", 1)[0] # بخش اصلی بدون نام

    # --- بررسی‌های ساختاری مخصوص هر پروتکل ---

    if proto_prefix_val == "vless":
        if '@' not in main_payload: return False, f"{proto_name_key}: علامت @ یافت نشد"
        if not re.search(r':\d{2,5}', main_payload): return False, f"{proto_name_key}: پورت یافت نشد"
        uuid_part = main_payload.split('@', 1)[0]
        uuid_pattern = r'^[a-fA-F0-9]{8}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{12}<span class="math-inline">'
if not re\.match\(uuid\_pattern, uuid\_part\)\:
return False, f"\{proto\_name\_key\}\: UUID معتبر \('\{uuid\_part\}'\) یافت نشد"
try\:
host\_part \= main\_payload\.split\('@',1\)\[1\]\.split\('\:',1\)\[0\]\.split\('?',1\)\[0\]
if not host\_part or not \(re\.match\(r'^\\d\{1,3\}\\\.\\d\{1,3\}\\\.\\d\{1,3\}\\\.\\d\{1,3\}</span>', host_part) or '.' in host_part):
                return False, f"{proto_name_key}: هاست نامعتبر ('{host_part}')"
        except IndexError:
            return False, f"{proto_name_key}: خطا در تجزیه هاست"

    elif proto_prefix_val == "vmess":
        if main_payload.startswith("ey"): # احتمالاً Base64 JSON
            try:
                # Base64 ممکن است padding نداشته باشد
                missing_padding = len(main_payload) % 4
                if missing_padding:
                    main_payload += '=' * (4 - missing_padding)
                decoded_json_str = base64.urlsafe_b64decode(main_payload).decode('utf-8')
                vmess_obj = json.loads(decoded_json_str)
                required_keys = ["v", "add", "port", "id", "net"] # "ps" اختیاری است
                if not all(k in vmess_obj for k in required_keys):
                    return False, f"{proto_name_key} (Base64): فیلدهای ضروری {required_keys} در JSON یافت نشد"
                uuid_pattern = r'^[a-fA-F0-9]{8}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{12}<span class="math-inline">'
if not re\.match\(uuid\_pattern, vmess\_obj\.get\("id", ""\)\)\:
return False, f"\{proto\_name\_key\} \(Base64\)\: UUID \(id\) نامعتبر در JSON"
except Exception as e\:
return False, f"\{proto\_name\_key\} \(Base64\)\: خطا در دیکد/تجزیه JSON\: \{str\(e\)\}"
else\: \# فرمت قدیمی‌تر VMess \(کمتر رایج برای اشتراک‌گذاری\)
if '@' not in main\_payload\: return False, f"\{proto\_name\_key\} \(non\-Base64\)\: @ یافت نشد"
if not re\.search\(r'\:\\d\{2,5\}', main\_payload\)\: return False, f"\{proto\_name\_key\} \(non\-Base64\)\: پورت یافت نشد"
uuid\_part \= main\_payload\.split\('@', 1\)\[0\]
uuid\_pattern \= r'^\[a\-fA\-F0\-9\]\{8\}\-?\[a\-fA\-F0\-9\]\{4\}\-?\[a\-fA\-F0\-9\]\{4\}\-?\[a\-fA\-F0\-9\]\{4\}\-?\[a\-fA\-F0\-9\]\{12\}</span>'
            if not re.match(uuid_pattern, uuid_part):
                return False, f"{proto_name_key} (non-Base64): UUID معتبر ('{uuid_part}') یافت نشد"

    elif proto_prefix_val == "trojan":
        if '@' not in main_payload: return False, f"{proto_name_key}: @ یافت نشد"
        if not re.search(r':\d{2,5}', main_payload): return False, f"{proto_name_key}: پورت یافت نشد"
        # رمز عبور تروجان می‌تواند هر چیزی باشد، پس UUID چک نمی‌کنیم.
        try:
            host_part = main_payload.split('@',1)[1].split(':',1)[0].split('?',1)[0]
            if not host_part or not (re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}<span class="math-inline">', host\_part\) or '\.' in host\_part\)\:
return False, f"\{proto\_name\_key\}\: هاست نامعتبر \('\{host\_part\}'\)"
except IndexError\:
return False, f"\{proto\_name\_key\}\: خطا در تجزیه هاست"
elif proto\_prefix\_val \=\= "ss"\: \# ShadowSocks
\# ss\://method\:pass@host\:port OR ss\://BASE64\(method\:pass@host\:port\) OR ss\://BASE64\(json\_config for other clients\)
\# یک مثال از شما ss\://BASE64\_VMESS\_JSON بود که اشتباه است\. ss\:// نباید با ساختار JSON ویمس بیاید\.
\# ما به دنبال فرمت ss\://method\:pass@host\:port یا ss\://BASE64\(method\:pass@host\:port\) هستیم
if '@' in main\_payload and re\.search\(r'\:\\d\{2,5\}', main\_payload\.split\('@',1\)\[\-1\]\)\:
\# فرمت method\:pass@host\:port
pass \# ساختار اولیه به نظر درست است
else\: \# احتمالاً Base64
try\:
decoded\_ss\_payload \= base64\.urlsafe\_b64decode\(main\_payload \+ '\=' \* \(\-len\(main\_payload\) % 4\)\)\.decode\('utf\-8'\)
if '@' not in decoded\_ss\_payload or not re\.search\(r'\:\\d\{2,5\}', decoded\_ss\_payload\.split\('@',1\)\[\-1\]\)\:
return False, f"\{proto\_name\_key\} \(Base64\)\: ساختار داخلی \(method\:pass@host\:port\) بعد از دیکد نامعتبر"
except Exception\:
\# اگر مثال ss\://\{vmess\_json\_base64\} را در نظر بگیریم، این باعث رد شدنش می‌شود که درست است\.
return False, f"\{proto\_name\_key\}\: فرمت Base64 نامعتبر یا ساختار داخلی غیرمنتظره"
elif proto\_prefix\_val \=\= "ssr"\:
\# ssr\://BASE64\_ENCODED\_STRING
try\:
decoded\_ssr\_payload \= base64\.urlsafe\_b64decode\(main\_payload \+ '\=' \* \(\-len\(main\_payload\) % 4\)\)\.decode\('utf\-8'\)
parts \= decoded\_ssr\_payload\.split\('\:'\)
if len\(parts\) < 6 \: return False, f"\{proto\_name\_key\}\: ساختار داخلی Base64 کمتر از 6 بخش دارد"
if not re\.match\(r'^\\d\{1,5\}</span>',parts[1]): return False, f"{proto_name_key}: پورت ('{parts[1]}') در ساختار داخلی Base64 نامعتبر"
        except Exception as e:
            return False, f"{proto_name_key}: خطا در دیکد Base64 یا ساختار داخلی: {str(e)}"

    elif proto_prefix_val == "tuic":
        if '@' not in main_payload: return False, f"{proto_name_key}: @ یافت نشد"
        if not re.search(r':\d{2,5}', main_payload): return False, f"{proto_name_key}: پورت یافت نشد"
        user_info = main_payload.split('@', 1)[0]
        if ':' not in user_info: return False, f"{proto_name_key}: فرمت 'UUID:Password' در بخش کاربر ('{user_info}') مورد انتظار است"
        tuic_uuid = user_info.split(':',1)[0]
        uuid_pattern = r'^[a-fA-F0-9]{8}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{12}<span class="math-inline">'
if not re\.match\(uuid\_pattern, tuic\_uuid\)\:
return False, f"\{proto\_name\_key\}\: UUID معتبر \('\{tuic\_uuid\}'\) در بخش کاربر یافت نشد"
try\:
host\_part \= main\_payload\.split\('@',1\)\[1\]\.split\('\:',1\)\[0\]\.split\('?',1\)\[0\]
if not host\_part or not \(re\.match\(r'^\\d\{1,3\}\\\.\\d\{1,3\}\\\.\\d\{1,3\}\\\.\\d\{1,3\}</span>', host_part) or '.' in host_part):
                return False, f"{proto_name_key}: هاست نامعتبر ('{host_part}')"
        except IndexError:
            return False, f"{proto_name_key}: خطا در تجزیه هاست"


    elif proto_prefix_val == "hy2":
        if '@' not in main_payload: return False, f"{proto_name_key}: @ یافت نشد"
        if not re.search(r':\d{2,5}', main_payload): return False, f"{proto_name_key}: پورت یافت نشد"
        # رمز می‌تواند هر چیزی باشد
        try:
            host_part = main_payload.split('@',1)[1].split(':',1)[0].split('?',1)[0]
            if not host_part or not (re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host_part) or '.' in host_part):
                return False, f"{proto_name_key}: هاست نامعتبر ('{host_part}')"
        except IndexError:
            return False, f"{proto_name_key}: خطا در تجزیه هاست"

    elif proto_prefix_val == "wireguard":
        # wg://KEY_MATERIAL@HOST:PORT?publickey=...&address=...
        if '@' not in main_payload: return False, f"{proto_name_key}: @ یافت نش
