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

# <<<--- تابع اعتبارسنجی به‌روز شده و تعدیل شده --->>>
def is_config_valid(config_string_original, min_len=20, max_len=2500, max_overall_percent_char_ratio=0.6, max_specific_percent25_count=10):
    """
    Checks if a config string looks potentially valid.
    Returns (True, None) if valid, or (False, "reason_string") if invalid.
    """
    config_string = config_string_original.strip() # حذف فاصله‌های اضافی ابتدا و انتها

    l = len(config_string)
    # 1. Check length
    if not (min_len <= l <= max_len):
        return False, f"طول نامعتبر ({l}). مورد انتظار: {min_len}-{max_len}"

    # 2. Check for excessive overall '%' characters if the string is long enough
    if l > 50 and (config_string.count('%') / l) > max_overall_percent_char_ratio:
        return False, f"تعداد زیاد کاراکتر % نسبت به طول کل ({config_string.count('%')}/{l})"

    # 3. Check for the specific problematic '%25' pattern if it's very frequent
    if config_string.count('%25') > max_specific_percent25_count:
        return False, f"تعداد زیاد تکرار '%25' ({config_string.count('%25')})"

    # 4. Must start with a known protocol
    proto_name_key = None # کلید پروتکل از PROTOCOL_CATEGORIES
    proto_prefix_val = None # خود پیشوند مثل vless, trojan
    for p_key in PROTOCOL_CATEGORIES:
        if config_string.lower().startswith(p_key.lower() + "://"):
            proto_name_key = p_key # ذخیره کلید اصلی برای استفاده در پیام‌ها
            proto_prefix_val = p_key.lower()
            break
    if not proto_prefix_val:
        return False, "پیشوند پروتکل معتبر یافت نشد"

    payload = config_string.split("://", 1)[1] # بخش بعد از ://

    # --- بررسی‌های ساختاری مخصوص هر پروتکل ---

    if proto_prefix_val == "vless":
        if '@' not in payload: return False, f"{proto_name_key}: علامت @ یافت نشد"
        if not re.search(r':\d{2,5}', payload): return False, f"{proto_name_key}: پورت یافت نشد"
        uuid_part = payload.split('@', 1)[0]
        uuid_pattern = r'^[a-fA-F0-9]{8}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{12}$'
        if not re.match(uuid_pattern, uuid_part):
            return False, f"{proto_name_key}: UUID معتبر ('{uuid_part}') یافت نشد"

    elif proto_prefix_val == "vmess":
        # Vmess can be vmess://BASE64 or vmess://uuid@host...
        # If it looks like it might not be full base64 (e.g. contains '@' early on)
        if '@' in payload.split('?',1)[0].split('#',1)[0] and not payload.startswith("ey"): # "ey" is common start for base64 json
            if '@' not in payload: return False, f"{proto_name_key} (non-base64): @ یافت نشد"
            if not re.search(r':\d{2,5}', payload): return False, f"{proto_name_key} (non-base64): پورت یافت نشد"
            uuid_part = payload.split('@', 1)[0]
            uuid_pattern = r'^[a-fA-F0-9]{8}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{12}$'
            if not re.match(uuid_pattern, uuid_part):
                return False, f"{proto_name_key} (non-base64): UUID معتبر ('{uuid_part}') یافت نشد"
        # Otherwise, for likely base64 vmess, we rely on length/percent checks and prefix.

    elif proto_prefix_val == "trojan":
        # Trojan password is not necessarily a UUID. Just check for @ and port.
        if '@' not in payload: return False, f"{proto_name_key}: @ یافت نشد"
        if not re.search(r':\d{2,5}', payload): return False, f"{proto_name_key}: پورت یافت نشد"

    elif proto_prefix_val == "ss": # ShadowSocks
        # ss://method:pass@host:port OR ss://BASE64(method:pass@host:port) OR ss://BASE64(json_config_for_other_clients)
        # If payload contains '@', it's likely method:pass@host:port. Check port.
        if '@' in payload:
            if not re.search(r':\d{2,5}', payload.split('@',1)[-1]): # Check port after last @
                 return False, f"{proto_name_key}: پورت بعد از @ یافت نشد"
        # If no '@' but is very short, could be ss://BASE64(method:pass) which is usually not directly usable.
        # If it's a longer Base64 (like example 4 from user), it might be a V2Ray-style SS JSON.
        # This is complex to validate without decoding. For now, if no '@' and not clearly base64 for other clients,
        # it might be too simple. But given example 4, we accept it if prefix is ss://
        # and it passes length/percent checks.

    elif proto_prefix_val == "ssr":
        # ssr://BASE64. No easy structural checks beyond prefix, length, %.
        pass

    elif proto_prefix_val in ["wireguard", "tuic", "hy2"]:
        if '@' not in payload: return False, f"{proto_name_key}: @ یافت نشد"
        if not re.search(r':\d{2,5}', payload): return False, f"{proto_name_key}: پورت یافت نشد"


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
    if not rejected_items:
        logging.info(f"No configs rejected in this run.")
        # Create a file saying no rejections if it doesn't exist or is empty
        if not os.path.exists(REJECTED_LOG_FILE) or os.path.getsize(REJECTED_LOG_FILE) == 0 :
             with open(REJECTED_LOG_FILE, 'w', encoding='utf-8') as f:
                f.write(f"# ⚠️ گزارش کانفیگ‌های رد شده (آخرین به‌روزرسانی: {datetime.now(pytz.timezone('Asia/Tehran')).strftime('%Y-%m-%d %H:%M:%S %Z')})\n\n")
                f.write("هیچ کانفیگی در این اجرا رد نشده است.\n")
        return

    tz = pytz.timezone('Asia/Tehran')
    now = datetime.now(tz)
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S %Z")

    md_content = f"# ⚠️ گزارش کانفیگ‌های رد شده (آخرین به‌روزرسانی: {timestamp})\n\n"
    md_content += "در این گزارش، کانفیگ‌هایی که توسط اسکریپت معتبر تشخیص داده نشده‌اند به همراه دلیل رد شدن و URL منبع لیست شده‌اند.\n\n"

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
    md_content += f"**توضیح:** فایل‌های کشورها فقط شامل کانفیگ‌هایی هستند که نام/پرچم کشور (با رعایت مرز کلمه برای مخفف‌ها) در **اسم خود کانفیگ (بعد از #)** پیدا شده باشد. کانفیگ‌های مشکوک و نامعتبر از نظر ساختاری فیلتر شده‌اند. گزارش کامل کانفیگ‌های رد شده را می‌توانید در [`{REJECTED_LOG_FILE}`](./{REJECTED_LOG_FILE}) مشاهده کنید.\n\n"

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
    final_all_protocols = {cat: set() for cat in PROTOCOL_CATEGORIES}
    rejected_configs_log = []

    logging.info("Processing pages & filtering configs...")
    for url, text in fetched_pages:
        if not text:
            continue

        page_matches = find_matches(text, categories)

        all_page_configs = set()
        for cat in PROTOCOL_CATEGORIES:
            if cat in page_matches:
                all_page_configs.update(page_matches[cat])

        for config in all_page_configs:
            is_valid, reason = is_config_valid(config)
            if not is_valid:
                rejected_configs_log.append({"config": config, "reason": reason, "url": url})
                if reason: # Log the reason only if specific reason is returned
                    logging.warning(f"REJECTED ('{reason}'): {config[:70]}... (URL: {url})")
                else: # Generic failure if no reason given by is_config_valid somehow
                    logging.warning(f"REJECTED (Generic): {config[:70]}... (URL: {url})")
                continue

            for cat in PROTOCOL_CATEGORIES:
                if config.lower().startswith(cat.lower() + "://"):
                     final_all_protocols[cat].add(config)
                     break
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
                            final_configs_by_country[country].add(config)
                            break
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

    generate_simple_readme(protocol_counts, country_counts)
    save_rejected_log(rejected_configs_log)

    logging.info("--- Script Finished ---")

if __name__ == "__main__":
    asyncio.run(main())
