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
REJECTED_LOG_FILE = 'rejected_configs_report.md' # نام فایل گزارش رد شده‌ها
REQUEST_TIMEOUT = 15
CONCURRENT_REQUESTS = 10

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- Protocol Categories ---
PROTOCOL_CATEGORIES = [
    "Vmess", "Vless", "Trojan", "ShadowSocks", "ShadowSocksR",
    "Tuic", "Hysteria2", "WireGuard"
]

# <<<--- تابع اعتبارسنجی به‌روز شده با بازگرداندن دلیل --->>>
def is_config_valid(config_string, min_len=20, max_len=2500, max_overall_percent_char_ratio=0.5, max_specific_percent25_count=10):
    """
    Checks if a config string looks potentially valid.
    Returns (True, None) if valid, or (False, "reason_string") if invalid.
    """
    l = len(config_string)
    if not (min_len <= l <= max_len):
        return False, f"طول نامعتبر ({l}). مورد انتظار: {min_len}-{max_len}"

    if l > 50 and (config_string.count('%') / l) > max_overall_percent_char_ratio:
        return False, f"تعداد زیاد کاراکتر % نسبت به طول کل ({config_string.count('%')}/{l})"

    if config_string.count('%25') > max_specific_percent25_count:
        return False, f"تعداد زیاد تکرار '%25' ({config_string.count('%25')})"

    proto_prefix = None
    for p in PROTOCOL_CATEGORIES:
        if config_string.lower().startswith(p.lower() + "://"):
            proto_prefix = p.lower()
            break
    if not proto_prefix:
        return False, "پیشوند پروتکل معتبر یافت نشد"

    # --- بررسی‌های ساختاری دیگر (می‌توانید این بخش را ساده‌تر یا پیچیده‌تر کنید) ---
    # مثال: برای VLESS/VMESS/TROJAN دنبال UUID بگردیم
    if proto_prefix in ["vless", "vmess", "trojan"]:
        uuid_part_match = re.search(r'([a-fA-F0-9]{8}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{12})', config_string)
        if not uuid_part_match:
            return False, f"UUID معتبر برای {proto_prefix} یافت نشد"
        # اگر UUID پیدا شد، بررسی کنیم که آیا قبل از @ آمده است
        if '@' in config_string and config_string.find(uuid_part_match.group(1)) > config_string.find('@'):
            return False, f"UUID برای {proto_prefix} بعد از @ یافت شد که نامعتبر است"


    # اگر به اینجا رسید، یعنی معتبر است (یا حداقل از فیلترهای فعلی گذشته)
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
    """Saves rejected configs to a Markdown file."""
    if not rejected_items:
        logging.info(f"No configs rejected in this run. If {REJECTED_LOG_FILE} exists, it won't be modified unless it contains previous rejections.")
        # Optionally create an empty file or a file saying "no rejections"
        # For now, just create it if there are items.
        if not os.path.exists(REJECTED_LOG_FILE) and not rejected_items:
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
        md_content += f"## کانفیگ:\n```text\n{config}\n```\n" # Use text for better rendering of long strings
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
    md_content += f"**توضیح:** فایل‌های کشورها فقط شامل کانفیگ‌هایی هستند که نام/پرچم کشور (با رعایت مرز کلمه برای مخفف‌ها) در **اسم خود کانفیگ (بعد از #)** پیدا شده باشد. کانفیگ‌های مشکوک (فیک) فیلتر شده‌اند. گزارش کامل کانفیگ‌های رد شده را می‌توانید در [`{REJECTED_LOG_FILE}`](./{REJECTED_LOG_FILE}) مشاهده کنید.\n\n" # <--- لینک اضافه شد

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
    rejected_configs_log = [] # <--- لیست برای نگهداری رد شده‌ها

    logging.info("Processing pages & filtering configs...")
    for url, text in fetched_pages: # <--- 'url' از اینجا می‌آید
        if not text:
            continue

        page_matches = find_matches(text, categories)

        all_page_configs = set()
        for cat in PROTOCOL_CATEGORIES:
            if cat in page_matches:
                all_page_configs.update(page_matches[cat])

        for config in all_page_configs:
            is_valid, reason = is_config_valid(config) # <--- دریافت دلیل
            if not is_valid:
                rejected_configs_log.append({"config": config, "reason": reason, "url": url}) # <--- اضافه کردن URL منبع
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
    save_rejected_log(rejected_configs_log) # <--- ذخیره گزارش رد شده‌ها

    logging.info("--- Script Finished ---")

if __name__ == "__main__":
    asyncio.run(main())
