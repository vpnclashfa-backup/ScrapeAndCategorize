import asyncio
import aiohttp
import json
import re
import logging
from bs4 import BeautifulSoup
import os # os از قبل import شده یا اگر نشده باید اضافه شود
import shutil
from datetime import datetime
import pytz
import base64
from urllib.parse import parse_qs, unquote

# --- Configuration ---
URLS_FILE = 'urls.txt'
KEYWORDS_FILE = 'keywords.json'
OUTPUT_DIR = 'output_configs' # این متغیر در ساخت لینک استفاده خواهد شد
README_FILE = 'README.md'
REQUEST_TIMEOUT = 15
CONCURRENT_REQUESTS = 10
MAX_CONFIG_LENGTH = 1500
MIN_PERCENT25_COUNT = 15

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- Protocol Categories ---
PROTOCOL_CATEGORIES = [
    "Vmess", "Vless", "Trojan", "ShadowSocks", "ShadowSocksR",
    "Tuic", "Hysteria2", "WireGuard"
]

DEFAULT_FLAG = "🏳️"

# ... (بقیه توابع کمکی مانند decode_base64, get_vmess_name, get_ssr_name, should_filter_config, fetch_url, find_matches, save_to_file بدون تغییر باقی می‌مانند) ...
# اطمینان حاصل کنید که find_matches و بقیه توابع در اینجا هستند

# --- Base64 Decoding Helper ---
def decode_base64(data):
    try:
        data = data.replace('_', '/').replace('-', '+')
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8')
    except Exception:
        return None

# --- Protocol Name Extraction Helpers ---
def get_vmess_name(vmess_link):
    if not vmess_link.startswith("vmess://"):
        return None
    try:
        b64_part = vmess_link[8:]
        decoded_str = decode_base64(b64_part)
        if decoded_str:
            vmess_json = json.loads(decoded_str)
            return vmess_json.get('ps')
    except Exception as e:
        logging.warning(f"Failed to parse Vmess name from {vmess_link[:30]}...: {e}")
    return None

def get_ssr_name(ssr_link):
    if not ssr_link.startswith("ssr://"):
        return None
    try:
        b64_part = ssr_link[6:]
        decoded_str = decode_base64(b64_part)
        if not decoded_str: return None
        parts = decoded_str.split('/?')
        if len(parts) < 2: return None
        params = parse_qs(parts[1])
        if 'remarks' in params and params['remarks']:
            remarks_b64 = params['remarks'][0]
            return decode_base64(remarks_b64)
    except Exception as e:
        logging.warning(f"Failed to parse SSR name from {ssr_link[:30]}...: {e}")
    return None

# --- New Filter Function ---
def should_filter_config(config):
    if 'i_love_' in config.lower():
        logging.warning(f"Filtering by keyword 'I_Love_': {config[:60]}...")
        return True
    percent25_count = config.count('%25')
    if percent25_count >= MIN_PERCENT25_COUNT:
        logging.warning(f"Filtering by high %25 count ({percent25_count}): {config[:60]}...")
        return True
    if len(config) >= MAX_CONFIG_LENGTH:
        logging.warning(f"Filtering by excessive length ({len(config)}): {config[:60]}...")
        return True
    if '%2525' in config:
        logging.warning(f"Filtering by '%2525' presence: {config[:60]}...")
        return True
    return False

async def fetch_url(session, url):
    try:
        async with session.get(url, timeout=REQUEST_TIMEOUT) as response:
            response.raise_for_status()
            html = await response.text()
            soup = BeautifulSoup(html, 'html.parser')
            text_content = ""
            for element in soup.find_all(['pre', 'code', 'p', 'div', 'li', 'span', 'td']):
                text_content += element.get_text(separator='\n', strip=True) + "\n"
            if not text_content:
                text_content = soup.get_text(separator=' ', strip=True)
            logging.info(f"Successfully fetched: {url}")
            return url, text_content
    except Exception as e:
        logging.warning(f"Failed to fetch or process {url}: {e}")
        return url, None

def find_matches(text, categories_with_patterns):
    matches = {category: set() for category in categories_with_patterns}
    for category, patterns in categories_with_patterns.items():
        for pattern_str in patterns:
            if len(pattern_str) < 4 and all(0x1F1E6 <= ord(char) <= 0x1F1FF for char in pattern_str):
                 continue
            try:
                if category in PROTOCOL_CATEGORIES:
                    pattern = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
                    found = pattern.findall(text)
                    if found:
                        cleaned_found = {item.strip() for item in found if item.strip()}
                        matches[category].update(cleaned_found)
            except re.error as e:
                logging.error(f"Regex error for '{pattern_str}' in category '{category}': {e}")
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


def generate_simple_readme(protocol_counts, country_counts, country_flags_map):
    tz = pytz.timezone('Asia/Tehran')
    now = datetime.now(tz)
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S %Z")

    md_content = f"# 📊 نتایج استخراج (آخرین به‌روزرسانی: {timestamp})\n\n"
    md_content += "این فایل به صورت خودکار ایجاد شده است.\n\n"
    md_content += "**توضیح:** فایل‌های کشورها فقط شامل کانفیگ‌هایی هستند که نام/پرچم کشور (با رعایت مرز کلمه برای مخفف‌ها) در **اسم کانفیگ** پیدا شده باشد. اسم کانفیگ ابتدا از بخش `#` لینک و در صورت نبود، از نام داخلی (برای Vmess/SSR) استخراج می‌شود.\n\n"
    md_content += "**نکته:** کانفیگ‌هایی که به شدت URL-Encode شده‌اند (حاوی تعداد زیادی `%25`، طولانی یا دارای کلمات کلیدی خاص) از نتایج حذف شده‌اند.\n\n"

    # --- بخش جدید برای ساخت لینک‌های raw ---
    github_repository = os.environ.get('GITHUB_REPOSITORY')  # مثلا 'username/reponame'
    github_ref_name = os.environ.get('GITHUB_REF_NAME')      # مثلا 'main' یا نام branch/tag

    base_url_for_link = ""
    if github_repository and github_ref_name:
        # ساخت URL پایه برای لینک‌های خام گیت‌هاب
        base_url_for_link = f"https://raw.githubusercontent.com/{github_repository}/{github_ref_name}"
    # ---------------------------------------

    md_content += "## 📁 فایل‌های پروتکل‌ها\n\n"
    if protocol_counts:
        md_content += "| پروتکل | تعداد کل | لینک |\n"
        md_content += "|---|---|---|\n"
        for category, count in sorted(protocol_counts.items()):
            file_name_display = f"{category}.txt"
            file_path_in_repo = f"{OUTPUT_DIR}/{category}.txt" # مسیر فایل در ریپازیتوری

            if base_url_for_link: # اگر در محیط گیت‌هاب اکشنز هستیم
                link_url = f"{base_url_for_link}/{file_path_in_repo}"
            else: # در غیر این صورت (مثلا اجرای محلی) از لینک نسبی استفاده کن
                link_url = f"./{file_path_in_repo}"
            
            md_content += f"| {category} | {count} | [`{file_name_display}`]({link_url}) |\n" # <--- لینک اصلاح شد
    else:
        md_content += "هیچ کانفیگ پروتکلی یافت نشد.\n"
    md_content += "\n"

    md_content += "## 🌍 فایل‌های کشورها (حاوی کانفیگ)\n\n"
    if country_counts:
        md_content += "| پرچم | کشور | تعداد کانفیگ مرتبط | لینک |\n"
        md_content += "|:---:|---|---|---|\n"
        for category, count in sorted(country_counts.items()):
            flag_emoji = country_flags_map.get(category, DEFAULT_FLAG)
            file_name_display = f"{category}.txt"
            file_path_in_repo = f"{OUTPUT_DIR}/{category}.txt" # مسیر فایل در ریپازیتوری

            if base_url_for_link: # اگر در محیط گیت‌هاب اکشنز هستیم
                link_url = f"{base_url_for_link}/{file_path_in_repo}"
            else: # در غیر این صورت (مثلا اجرای محلی) از لینک نسبی استفاده کن
                link_url = f"./{file_path_in_repo}"

            md_content += f"| {flag_emoji} | {category} | {count} | [`{file_name_display}`]({link_url}) |\n" # <--- لینک اصلاح شد
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
        logging.critical(f"Input files not found. Ensure {URLS_FILE} and {KEYWORDS_FILE} exist.")
        return

    with open(URLS_FILE, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]
    with open(KEYWORDS_FILE, 'r', encoding='utf-8') as f:
        all_categories_data = json.load(f)

    patterns_for_protocols = {}
    country_keywords_map = {}
    country_flags_from_keywords = {} 

    for category_name, keywords_or_patterns_list in all_categories_data.items():
        if category_name in PROTOCOL_CATEGORIES:
            patterns_for_protocols[category_name] = keywords_or_patterns_list
        else: 
            country_keywords_map[category_name] = []
            if keywords_or_patterns_list: 
                potential_flag = keywords_or_patterns_list[-1]
                is_likely_flag = (len(potential_flag) == 2 and all(0x1F1E6 <= ord(char) <= 0x1F1FF for char in potential_flag)) or \
                                 (len(potential_flag) == 1 and ord(potential_flag) > 255) 

                if is_likely_flag and len(keywords_or_patterns_list) > 1 : 
                    country_flags_from_keywords[category_name] = potential_flag
                    country_keywords_map[category_name] = keywords_or_patterns_list[:-1] 
                elif is_likely_flag and len(keywords_or_patterns_list) == 1: 
                     country_flags_from_keywords[category_name] = potential_flag
                     country_keywords_map[category_name] = [category_name]
                else: 
                    country_keywords_map[category_name] = keywords_or_patterns_list
            else: 
                 country_keywords_map[category_name] = [category_name]


    country_category_names = list(country_keywords_map.keys())

    logging.info(f"Loaded {len(urls)} URLs.")
    logging.info(f"Protocol categories: {list(patterns_for_protocols.keys())}")
    logging.info(f"Country categories: {country_category_names}")
    logging.info(f"Extracted flags for: {list(country_flags_from_keywords.keys())}")

    sem = asyncio.Semaphore(CONCURRENT_REQUESTS)
    async def fetch_with_sem(session, url):
        async with sem:
            return await fetch_url(session, url)
    async with aiohttp.ClientSession() as session:
        fetched_pages = await asyncio.gather(*[fetch_with_sem(session, url) for url in urls])

    final_configs_by_country = {cat: set() for cat in country_category_names}
    final_all_protocols = {cat: set() for cat in PROTOCOL_CATEGORIES}

    logging.info("Processing pages for config extraction and name association...")
    for url, text in fetched_pages:
        if not text:
            continue

        page_protocol_matches = find_matches(text, patterns_for_protocols)
        all_page_configs_filtered = set()
        for protocol_cat, configs_found in page_protocol_matches.items():
            for config in configs_found:
                if should_filter_config(config):
                    continue
                all_page_configs_filtered.add(config)
                if protocol_cat in final_all_protocols:
                    final_all_protocols[protocol_cat].add(config)

        for config in all_page_configs_filtered:
            name_to_check = None
            if '#' in config:
                try:
                    potential_name = config.split('#', 1)[1]
                    name_to_check = unquote(potential_name).strip()
                    if not name_to_check: name_to_check = None
                except IndexError: pass

            if not name_to_check:
                if config.startswith('ssr://'): name_to_check = get_ssr_name(config)
                elif config.startswith('vmess://'): name_to_check = get_vmess_name(config)

            if not name_to_check: continue

            for country_name, keywords_for_country in country_keywords_map.items():
                for keyword in keywords_for_country:
                    match_found = False
                    if not keyword.strip(): continue
                    is_abbr = (len(keyword) == 2 or len(keyword) == 3) and re.match(r'^[A-Z]+$', keyword)
                    try:
                        if is_abbr:
                            pattern = r'\b' + re.escape(keyword) + r'\b'
                            if re.search(pattern, name_to_check, re.IGNORECASE):
                                match_found = True
                        else:
                            if re.search(r'\b' + re.escape(keyword) + r'\b', name_to_check, re.IGNORECASE) or \
                               keyword.lower() in name_to_check.lower():
                                match_found = True
                    except re.error as e:
                        logging.error(f"Regex error during country keyword matching for '{keyword}' in '{name_to_check}': {e}")
                        continue
                    if match_found:
                        final_configs_by_country[country_name].add(config)
                        break 
                if match_found:
                    break 

    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    logging.info(f"Saving files to directory: {OUTPUT_DIR}")

    protocol_counts = {}
    country_counts = {}

    for category, items in final_all_protocols.items():
        if items: 
            saved, count = save_to_file(OUTPUT_DIR, category, items)
            if saved: protocol_counts[category] = count

    for category, items in final_configs_by_country.items():
        if items: 
            saved, count = save_to_file(OUTPUT_DIR, category, items)
            if saved: country_counts[category] = count

    generate_simple_readme(protocol_counts, country_counts, country_flags_from_keywords)
    logging.info("--- Script Finished ---")

if __name__ == "__main__":
    asyncio.run(main())
