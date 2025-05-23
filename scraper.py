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
import base64
import urllib.parse

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
def is_config_valid(config_string_original, proto_prefix_val, min_len=20, max_len=3000, max_overall_percent_char_ratio=0.6, max_specific_percent25_count=10):
    """
    Checks if a config string has a valid structure for its specific protocol.
    Returns (True, None) if valid, or (False, "reason_string") if invalid.
    """
    config_string = config_string_original.strip()
    l = len(config_string)

    if not (min_len <= l <= max_len):
        return False, f"طول نامعتبر ({l}). مورد انتظار: {min_len}-{max_len}"

    if l > 70 and (config_string.count('%') / l) > max_overall_percent_char_ratio :
        return False, f"تعداد بسیار زیاد کاراکتر % ({config_string.count('%')})"
    if config_string.count('%25') > max_specific_percent25_count:
        return False, f"تعداد زیاد تکرار '%25' ({config_string.count('%25')})"

    # proto_prefix_val should already be determined and passed to this function
    if not proto_prefix_val:
        return False, "پیشوند پروتکل برای اعتبارسنجی مشخص نشده است (خطای داخلی)"

    payload = ""
    if "://" in config_string:
        payload = config_string.split("://", 1)[1]
    else:
        return False, "فرمت URI نامعتبر (بدون ://)" # Should not happen if find_matches is correct

    main_payload = payload.split("#", 1)[0] # بخش اصلی بدون نام

    # --- تعیین نام کلید پروتکل برای پیام‌های خطا ---
    proto_name_key = proto_prefix_val.capitalize() # For messages, e.g. "Vless"
    # Handle specific capitalizations if needed, e.g., from PROTOCOL_CATEGORIES list
    for key_in_list in PROTOCOL_CATEGORIES:
        if key_in_list.lower() == proto_prefix_val:
            proto_name_key = key_in_list
            break


    # --- بررسی‌های ساختاری مخصوص هر پروتکل ---

    if proto_prefix_val == "vless":
        if '@' not in main_payload: return False, f"{proto_name_key}: علامت @ یافت نشد"
        if not re.search(r':\d{2,5}', main_payload): return False, f"{proto_name_key}: پورت یافت نشد"
        uuid_part = main_payload.split('@', 1)[0]
        uuid_pattern = r'^[a-fA-F0-9]{8}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{12}$'
        if not re.match(uuid_pattern, uuid_part):
            return False, f"{proto_name_key}: UUID معتبر در بخش کاربر ('{uuid_part}') یافت نشد"
        try:
            host_part = main_payload.split('@',1)[1].split(':',1)[0].split('?',1)[0]
            if not host_part or not (re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host_part) or '.' in host_part):
                return False, f"{proto_name_key}: هاست نامعتبر ('{host_part}')"
        except IndexError:
            return False, f"{proto_name_key}: خطا در تجزیه هاست"

    elif proto_prefix_val == "vmess":
        if main_payload.startswith("ey"): # احتمالاً Base64 JSON
            try:
                missing_padding = len(main_payload) % 4
                if missing_padding:
                    main_payload_padded = main_payload + '=' * (4 - missing_padding)
                else:
                    main_payload_padded = main_payload
                decoded_json_str = base64.urlsafe_b64decode(main_payload_padded).decode('utf-8')
                vmess_obj = json.loads(decoded_json_str)
                required_keys = ["v", "add", "port", "id", "net"]
                if not all(k in vmess_obj for k in required_keys):
                    return False, f"{proto_name_key} (Base64): فیلدهای ضروری {required_keys} در JSON یافت نشد"
                uuid_pattern = r'^[a-fA-F0-9]{8}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{12}$'
                if "id" in vmess_obj and not re.match(uuid_pattern, str(vmess_obj.get("id", ""))): # Ensure ID is string
                    return False, f"{proto_name_key} (Base64): UUID (id) نامعتبر در JSON"
            except Exception as e:
                return False, f"{proto_name_key} (Base64): خطا در دیکد/تجزیه JSON: {str(e)}"
        else: # فرمت قدیمی‌تر VMess
            if '@' not in main_payload: return False, f"{proto_name_key} (non-Base64): @ یافت نشد"
            if not re.search(r':\d{2,5}', main_payload): return False, f"{proto_name_key} (non-Base64): پورت یافت نشد"
            uuid_part = main_payload.split('@', 1)[0]
            uuid_pattern = r'^[a-fA-F0-9]{8}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{12}$'
            if not re.match(uuid_pattern, uuid_part):
                return False, f"{proto_name_key} (non-Base64): UUID معتبر ('{uuid_part}') یافت نشد"

    elif proto_prefix_val == "trojan":
        if '@' not in main_payload: return False, f"{proto_name_key}: @ یافت نشد"
        if not re.search(r':\d{2,5}', main_payload): return False, f"{proto_name_key}: پورت یافت نشد"
        try:
            host_part = main_payload.split('@',1)[1].split(':',1)[0].split('?',1)[0]
            if not host_part or not (re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host_part) or '.' in host_part):
                return False, f"{proto_name_key}: هاست نامعتبر ('{host_part}')"
        except IndexError:
            return False, f"{proto_name_key}: خطا در تجزیه هاست"

    elif proto_prefix_val == "ss": # ShadowSocks
        if '@' in main_payload and re.search(r':\d{2,5}', main_payload.split('@',1)[-1]):
            pass # ساختار user:pass@host:port اولیه به نظر درست است
        else: # احتمالاً فرمت Base64 کامل (SIP002)
            try:
                # برای ss://BASE64، کل main_payload باید Base64 باشد
                decoded_ss_payload = base64.urlsafe_b64decode(main_payload + '=' * (-len(main_payload) % 4)).decode('utf-8')
                # پس از دیکد کردن، انتظار داریم user@host:port یا ساختار JSON ببینیم.
                # یک بررسی ساده: آیا @ و :پورت در رشته دیکد شده وجود دارد؟
                # این ممکن است برای فرمت‌های SIP002 JSON خیلی ساده باشد، اما از رد کردن بی‌دلیل جلوگیری می‌کند.
                if not ('@' in decoded_ss_payload and re.search(r':\d{2,5}', decoded_ss_payload.split('@',1)[-1])):
                    # اگر ساختار user@host:port نبود، ممکن است JSON باشد.
                    # اینجا می‌توانیم یک بررسی اولیه برای JSON بودن انجام دهیم.
                    try:
                        json.loads(decoded_ss_payload) # آیا JSON معتبر است؟
                        # اگر JSON بود، فعلا قبول می‌کنیم. بررسی دقیق‌تر فیلدهای JSON پیچیده است.
                    except json.JSONDecodeError:
                        return False, f"{proto_name_key} (Base64): ساختار داخلی بعد از دیکد، نه user@host:port است و نه JSON معتبر"
            except Exception:
                 return False, f"{proto_name_key}: فرمت Base64 نامعتبر"

    elif proto_prefix_val == "ssr":
        try:
            if not isinstance(main_payload, str):
                return False, f"{proto_name_key}: بخش اصلی Base64 یک رشته نیست"
            decoded_ssr_payload = base64.urlsafe_b64decode(main_payload + '=' * (-len(main_payload) % 4)).decode('utf-8')
            parts = decoded_ssr_payload.split(':')
            if len(parts) < 6 : return False, f"{proto_name_key}: ساختار داخلی Base64 کمتر از 6 بخش دارد"
            if not re.match(r'^\d{1,5}$',parts[1]): return False, f"{proto_name_key}: پورت ('{parts[1]}') در ساختار داخلی Base64 نامعتبر"
        except Exception as e:
            return False, f"{proto_name_key}: خطا در دیکد Base64 یا ساختار داخلی: {str(e)}"

    elif proto_prefix_val == "tuic":
        if '@' not in main_payload: return False, f"{proto_name_key}: @ یافت نشد"
        if not re.search(r':\d{2,5}', main_payload): return False, f"{proto_name_key}: پورت یافت نشد"
        user_info = main_payload.split('@', 1)[0]
        if ':' not in user_info: return False, f"{proto_name_key}: فرمت 'UUID:Password' در بخش کاربر ('{user_info}') مورد انتظار است"
        tuic_uuid = user_info.split(':',1)[0]
        uuid_pattern = r'^[a-fA-F0-9]{8}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{12}$'
        if not re.match(uuid_pattern, tuic_uuid):
            return False, f"{proto_name_key}: UUID معتبر ('{tuic_uuid}') در بخش کاربر یافت نشد"
        try:
            host_part = main_payload.split('@',1)[1].split(':',1)[0].split('?',1)[0]
            if not host_part or not (re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host_part) or '.' in host_part):
                return False, f"{proto_name_key}: هاست نامعتبر ('{host_part}')"
        except IndexError:
            return False, f"{proto_name_key}: خطا در تجزیه هاست"


    elif proto_prefix_val == "hy2":
        if '@' not in main_payload: return False, f"{proto_name_key}: @ یافت نشد"
        if not re.search(r':\d{2,5}', main_payload): return False, f"{proto_name_key}: پورت یافت نشد"
        try:
            host_part = main_payload.split('@',1)[1].split(':',1)[0].split('?',1)[0]
            if not host_part or not (re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host_part) or '.' in host_part):
                return False, f"{proto_name_key}: هاست نامعتبر ('{host_part}')"
        except IndexError:
            return False, f"{proto_name_key}: خطا در تجزیه هاست"

    elif proto_prefix_val == "wireguard":
        if '@' not in main_payload: return False, f"{proto_name_key}: @ یافت نشد"
        if not re.search(r':\d{2,5}', main_payload): return False, f"{proto_name_key}: پورت یافت نشد"
        query_part = main_payload.split('?', 1)[1] if '?' in main_payload else ""
        if 'publickey=' not in query_part.lower(): return False, f"{proto_name_key}: پارامتر 'publickey' یافت نشد"
        # address= پارامتر مهمی است اما در برخی کانفیگ های وایرگارد ممکن است در بخش دیگری باشد یا از طریق سرور تعیین شود
        # if 'address=' not in query_part.lower(): return False, f"{proto_name_key}: پارامتر 'address' یافت نشد"
        try:
            host_part = main_payload.split('@',1)[1].split(':',1)[0].split('?',1)[0]
            if not host_part or not (re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host_part) or '.' in host_part):
                return False, f"{proto_name_key}: هاست نامعتبر ('{host_part}')"
        except IndexError:
            return False, f"{proto_name_key}: خطا در تجزیه هاست"

    return True, None
# <<<--- پایان تابع اعتبارسنجی --->>>

async def fetch_url(session, url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        async with session.get(url, timeout=REQUEST_TIMEOUT, headers=headers) as response:
            response.raise_for_status()
            html = await response.text()
            soup = BeautifulSoup(html, 'html.parser')
            text = soup.get_text(separator=' ', strip=True)
            logging.info(f"Successfully fetched: {url}")
            return url, text
    except Exception as e:
        logging.warning(f"Failed to fetch or process {url}: {e}")
        return url, None

def find_matches(text, categories):
    matches = {category: set() for category in categories}
    for category, patterns in categories.items():
        for pattern_str in patterns:
            try:
                pattern = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
                found = pattern.findall(text)
                if found:
                    matches[category].update(found)
            except re.error as e:
                logging.error(f"Regex error for '{pattern_str}': {e}")
    return {k: v for k, v in matches.items() if v}

def save_to_file(directory, category_name, items_set):
    if not items_set:
        return False, 0
    file_path = os.path.join(directory, f"{category_name}.txt")
    count = len(items_set)
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            for item in sorted(list(items_set)):
                f.write(f"{item}\n")
        logging.info(f"Saved {count} items to {file_path}")
        return True, count
    except Exception as e:
        logging.error(f"Failed to write file {file_path}: {e}")
        return False, 0

def save_rejected_log(rejected_items):
    tz = pytz.timezone('Asia/Tehran')
    now = datetime.now(tz)
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S %Z")

    md_content = f"# ⚠️ گزارش کانفیگ‌های رد شده (آخرین به‌روزرسانی: {timestamp})\n\n"
    md_content += "در این گزارش، کانفیگ‌هایی که توسط اسکریپت معتبر تشخیص داده نشده‌اند به همراه دلیل رد شدن و URL منبع لیست شده‌اند.\n\n"

    if not rejected_items:
        md_content += "هیچ کانفیگی در این اجرا رد نشده است.\n"
    else:
        for item in rejected_items:
            config = item["config"]
            reason = item["reason"]
            source_url = item["url"]
            md_content += f"## کانفیگ:\n```text\n{config}\n```\n"
            md_content += f"**دلیل رد شدن:** {reason}\n\n"
            md_content += f"**منبع URL:** `{source_url}`\n\n"
            md_content += "---\n\n"

    try:
        with open(REJECTED_LOG_FILE, 'w', encoding='utf-8') as f:
            f.write(md_content)
        logging.info(f"Generated {REJECTED_LOG_FILE} with {len(rejected_items)} entries.")
    except Exception as e:
        logging.error(f"Failed to write {REJECTED_LOG_FILE}: {e}")


def generate_simple_readme(protocol_counts, country_counts):
    tz = pytz.timezone('Asia/Tehran')
    now = datetime.now(tz)
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S %Z")

    md_content = f"# 📊 نتایج استخراج (آخرین به‌روزرسانی: {timestamp})\n\n"
    md_content += "این فایل به صورت خودکار ایجاد شده است.\n\n"
    md_content += f"**توضیح:** فایل‌های کشورها فقط شامل کانفیگ‌هایی هستند که نام/پرچم کشور (با رعایت مرز کلمه برای مخفف‌ها) در **اسم خود کانفیگ (بعد از #)** پیدا شده باشد. کانفیگ‌های نامعتبر از نظر ساختاری فیلتر شده‌اند. گزارش کامل کانفیگ‌های رد شده را می‌توانید در [`{REJECTED_LOG_FILE}`](./{REJECTED_LOG_FILE}) مشاهده کنید.\n\n"

    md_content += "## 📁 فایل‌های پروتکل‌ها\n\n"
    if protocol_counts:
        md_content += "| پروتکل | تعداد کل | لینک |\n"
        md_content += "|---|---|---|\n"
        for category, count in sorted(protocol_counts.items()):
            md_content += f"| {category} | {count} | [`{category}.txt`](./{OUTPUT_DIR}/{category}.txt) |\n"
    else:
        md_content += "هیچ کانفیگ پروتکلی یافت نشد.\n"
    md_content += "\n"

    md_content += "## 🌍 فایل‌های کشورها (حاوی کانفیگ)\n\n"
    if country_counts:
        md_content += "| کشور | تعداد کانفیگ مرتبط | لینک |\n"
        md_content += "|---|---|---|\n"
        for category, count in sorted(country_counts.items()):
            md_content += f"| {category} | {count} | [`{category}.txt`](./{OUTPUT_DIR}/{category}.txt) |\n"
    else:
        md_content += "هیچ کانفیگ مرتبط با کشوری یافت نشد.\n"
    md_content += "\n"

    try:
        with open(README_FILE, 'w', encoding='utf-8') as f:
            f.write(md_content)
        logging.info(f"Successfully generated {README_FILE}")
    except Exception as e:
        logging.error(f"Failed to write {README_FILE}: {e}")


async def main():
    if not os.path.exists(URLS_FILE) or not os.path.exists(KEYWORDS_FILE):
        logging.critical("Input files not found.")
        return

    with open(URLS_FILE, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]
    with open(KEYWORDS_FILE, 'r', encoding='utf-8') as f:
        categories = json.load(f)

    country_categories = {cat: keywords for cat, keywords in categories.items() if cat not in PROTOCOL_CATEGORIES}
    country_category_names = list(country_categories.keys())

    logging.info(f"Loaded {len(urls)} URLs and "
                 f"{len(categories)} categories.")

    tasks = []
    sem = asyncio.Semaphore(CONCURRENT_REQUESTS)
    async def fetch_with_sem(session, url):
        async with sem:
            return await fetch_url(session, url)
    async with aiohttp.ClientSession() as session:
        fetched_pages = await asyncio.gather(*[fetch_with_sem(session, url) for url in urls])

    final_configs_by_country = {cat: set() for cat in country_category_names}
    final_all_protocols = {cat_key: set() for cat_key in PROTOCOL_CATEGORIES} # Use keys from list
    rejected_configs_log = []

    logging.info("Processing pages & filtering configs...")
    for url, text in fetched_pages:
        if not text:
            continue

        page_matches = find_matches(text, categories)

        all_page_configs_found_by_regex = set()
        for cat_key in PROTOCOL_CATEGORIES:
            if cat_key in page_matches:
                all_page_configs_found_by_regex.update(page_matches[cat_key])

        for config in all_page_configs_found_by_regex:
            current_proto_prefix_val = None
            # Determine the protocol prefix based on PROTOCOL_CATEGORIES
            for p_key_check in PROTOCOL_CATEGORIES:
                if config.lower().startswith(p_key_check.lower() + "://"):
                    current_proto_prefix_val = p_key_check.lower()
                    break
            
            # Pass the original config and determined prefix to validation
            is_valid, reason = is_config_valid(config, current_proto_prefix_val)

            if not is_valid:
                rejected_configs_log.append({"config": config, "reason": reason, "url": url})
                # logging.warning(f"REJECTED ('{reason}'): {config[:70]}... (URL: {url})") # Logged inside is_config_valid
                continue

            # Add to its main protocol list using the original key from PROTOCOL_CATEGORIES
            actual_protocol_category_key = None
            if current_proto_prefix_val: # Make sure a prefix was actually found
                for p_key_main in PROTOCOL_CATEGORIES:
                    if current_proto_prefix_val == p_key_main.lower():
                        actual_protocol_category_key = p_key_main
                        break
            
            if actual_protocol_category_key:
                 final_all_protocols[actual_protocol_category_key].add(config)
            
            # Associate with country if name matches
            if '#' in config:
                try:
                    name_part = config.split('#', 1)[1]
                except IndexError:
                    continue

                for country, keywords in country_categories.items():
                    for keyword in keywords:
                        match_found = False
                        is_abbr = (len(keyword) == 2 or len(keyword) == 3) and re.match(r'^[A-Z]+$', keyword)

                        if is_abbr:
                            pattern = r'\b' + re.escape(keyword) + r'\b'
                            if re.search(pattern, name_part, re.IGNORECASE):
                                match_found = True
                        else:
                            if keyword.lower() in name_part.lower():
                                match_found = True

                        if match_found:
                            # DEBUG for specific country
                            # if country == "Bangladesh":
                            #    logging.warning(f"DEBUG: Adding '{config}' to 'Bangladesh' because keyword '{keyword}' matched name '{name_part}'.")
                            final_configs_by_country[country].add(config)
                            break
    # --- Save Output Files ---
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    logging.info(f"Saving files to directory: {OUTPUT_DIR}")

    protocol_counts = {}
    country_counts = {}

    for category, items in final_all_protocols.items():
        saved, count = save_to_file(OUTPUT_DIR, category, items)
        if saved: protocol_counts[category] = count

    for category, items in final_configs_by_country.items():
        saved, count = save_to_file(OUTPUT_DIR, category, items)
        if saved: country_counts[category] = count

    # --- Generate README.md & Rejection Log ---
    generate_simple_readme(protocol_counts, country_counts)
    save_rejected_log(rejected_configs_log)

    logging.info("--- Script Finished ---")

if __name__ == "__main__":
    asyncio.run(main())
