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
from urllib.parse import parse_qs, unquote

# --- Configuration ---
URLS_FILE = 'urls.txt'
KEYWORDS_FILE = 'keywords.json'
OUTPUT_DIR = 'output_configs'
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

# --- Helper function to check for Persian-like text ---
def is_persian_like(text):
    """
    Checks if a string is predominantly Persian by looking for Arabic script characters
    and the absence of Latin characters.
    """
    if not isinstance(text, str) or not text.strip():
        return False
    has_persian_char = False
    has_latin_char = False
    for char in text:
        # Arabic Unicode block (covers Persian, Arabic, Urdu, etc.)
        # همچنین حروف یای فارسی و کاف فارسی را پوشش می‌دهد.
        if '\u0600' <= char <= '\u06FF' or char in ['\u200C', '\u200D']: # ZWNJ and ZWJ
            has_persian_char = True
        elif 'a' <= char.lower() <= 'z':
            has_latin_char = True
        # اگر کاراکترهای دیگری (مثلا اعداد یا سیمبول‌های رایج) باشند، فعلا نادیده می‌گیریم
        # و فقط بر اساس وجود فارسی و نبود لاتین تصمیم می‌گیریم.

    return has_persian_char and not has_latin_char

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
        if not decoded_str:
            return None
        parts = decoded_str.split('/?')
        if len(parts) < 2:
            return None
        params_str = parts[1]
        params = parse_qs(params_str)
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

def find_matches(text, categories_data):
    matches = {category: set() for category in categories_data}
    for category, patterns in categories_data.items():
        for pattern_str in patterns:
            if not isinstance(pattern_str, str):
                continue
            try:
                is_protocol_pattern = any(proto_prefix in pattern_str for proto_prefix in [p.lower() + "://" for p in PROTOCOL_CATEGORIES])
                if category in PROTOCOL_CATEGORIES or is_protocol_pattern:
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

<<<<<<< HEAD
# --- تابع generate_simple_readme با قابلیت نمایش نام فارسی ---
def generate_simple_readme(protocol_counts, country_counts, all_keywords_data, github_repo_path="10ium/ScrapeAndCategorize", github_branch="main"):
=======
# --- تابع اصلاح شده generate_simple_readme ---
def generate_simple_readme(protocol_counts, country_counts, all_keywords_data, github_repo_path="10ium/ScrapeAndCategorize", github_branch="main"):
    """Generates README.md with country flags/codes before country name in the same column."""
>>>>>>> 80b6e0fbf644d44f4576259ce2a8e0a0d617b228
    tz = pytz.timezone('Asia/Tehran')
    now = datetime.now(tz)
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S %Z")

    raw_github_base_url = f"https://raw.githubusercontent.com/{github_repo_path}/refs/heads/{github_branch}/{OUTPUT_DIR}"

    md_content = f"# 📊 نتایج استخراج (آخرین به‌روزرسانی: {timestamp})\n\n"
    md_content += "این فایل به صورت خودکار ایجاد شده است.\n\n"
    md_content += "**توضیح:** فایل‌های کشورها فقط شامل کانفیگ‌هایی هستند که نام/پرچم کشور (با رعایت مرز کلمه برای مخفف‌ها) در **اسم کانفیگ** پیدا شده باشد. اسم کانفیگ ابتدا از بخش `#` لینک و در صورت نبود، از نام داخلی (برای Vmess/SSR) استخراج می‌شود.\n\n"
    md_content += "**نکته:** کانفیگ‌هایی که به شدت URL-Encode شده‌اند (حاوی تعداد زیادی `%25`، طولانی یا دارای کلمات کلیدی خاص) از نتایج حذف شده‌اند.\n\n"

    md_content += "## 📁 فایل‌های پروتکل‌ها\n\n"
    if protocol_counts:
        md_content += "| پروتکل | تعداد کل | لینک |\n"
        md_content += "|---|---|---|\n"
        for category_name, count in sorted(protocol_counts.items()):
            file_link = f"{raw_github_base_url}/{category_name}.txt"
            md_content += f"| {category_name} | {count} | [`{category_name}.txt`]({file_link}) |\n"
    else:
        md_content += "هیچ کانفیگ پروتکلی یافت نشد.\n"
    md_content += "\n"

    md_content += "## 🌍 فایل‌های کشورها (حاوی کانفیگ)\n\n"
    if country_counts:
        # هدر جدول کشورها به ۳ ستون بازگشت
        md_content += "| کشور | تعداد کانفیگ مرتبط | لینک |\n"
        md_content += "|---|---|---|\n"
        for country_category_name, count in sorted(country_counts.items()):
<<<<<<< HEAD
            item_to_display_as_flag = ""
            persian_name_str = ""
=======
            # flag_or_code_str نمایش دهنده چیزی است که از انتهای لیست کلیدواژه ها استخراج می شود
            # (چه ایموجی پرچم باشد چه کد کشور)
            flag_or_code_str = ""
>>>>>>> 80b6e0fbf644d44f4576259ce2a8e0a0d617b228

            if country_category_name in all_keywords_data:
                keywords_list = all_keywords_data[country_category_name]
                if keywords_list and isinstance(keywords_list, list):
<<<<<<< HEAD
                    # 1. استخراج پرچم/کد (با منطق قبلی)
                    for item in keywords_list:
                        if isinstance(item, str) and (2 <= len(item) <= 7):
                            if not item.isalnum(): # اگر صرفا حروف و عدد نباشد (احتمالا ایموجی)
                                item_to_display_as_flag = item
                                break
                    if not item_to_display_as_flag and keywords_list: # Fallback
                        potential_last_item = keywords_list[-1]
                        if isinstance(potential_last_item, str) and (1 <= len(potential_last_item) <= 7):
                            item_to_display_as_flag = potential_last_item
                    
                    # 2. استخراج نام فارسی
                    for item in keywords_list:
                        if isinstance(item, str):
                            if item == item_to_display_as_flag: # نباید خود پرچم/کد باشد
                                continue
                            if item.lower() == country_category_name.lower(): # نباید خود کلید اصلی (معمولا انگلیسی) باشد
                                continue
                            if len(item) in [2,3] and item.isupper() and item.isalpha(): # نباید کد کوتاه کشور باشد
                                continue
                            
                            if is_persian_like(item): # تابع کمکی برای تشخیص فارسی
                                persian_name_str = item
                                break # اولین نام فارسی پیدا شده کافی است
            
            # 3. ساخت متن نهایی برای ستون "کشور"
            display_parts = []
            if item_to_display_as_flag:
                display_parts.append(item_to_display_as_flag)
            
            display_parts.append(country_category_name) # نام اصلی (کلید)

            if persian_name_str:
                display_parts.append(f"({persian_name_str})")
            
            country_display_text = " ".join(display_parts)
            
            file_link = f"{raw_github_base_url}/{country_category_name}.txt"
            link_text = f"{country_category_name}.txt"
=======
                    # فرض بر این است که آخرین آیتم در لیست، همان چیزی است که باید نمایش داده شود (پرچم یا کد)
                    potential_display_item = keywords_list[-1]
                    # بررسی اولیه برای طول معمول پرچم‌ها یا کدهای کشور
                    if isinstance(potential_display_item, str) and 1 <= len(potential_display_item) <= 7:
                        flag_or_code_str = potential_display_item

            file_link = f"{raw_github_base_url}/{country_category_name}.txt"
            link_text = f"{country_category_name}.txt" # متن لینک فقط نام فایل است

            # ترکیب پرچم/کد با نام کشور در ستون اول
            country_display_text = country_category_name
            if flag_or_code_str: # اگر چیزی (پرچم یا کد) استخراج شده باشد
                country_display_text = f"{flag_or_code_str} {country_category_name}"
            
>>>>>>> 80b6e0fbf644d44f4576259ce2a8e0a0d617b228
            md_content += f"| {country_display_text} | {count} | [`{link_text}`]({file_link}) |\n"
    else:
        md_content += "هیچ کانفیگ مرتبط با کشوری یافت نشد.\n"
    md_content += "\n"

    try:
        with open(README_FILE, 'w', encoding='utf-8') as f:
            f.write(md_content)
        logging.info(f"Successfully generated {README_FILE}")
    except Exception as e:
        logging.error(f"Failed to write {README_FILE}: {e}")

# تابع main و بقیه توابع کمکی باید مانند نسخه قبلی باشند که all_keywords_data
# را به درستی مدیریت می‌کردند. فقط generate_simple_readme تغییر کرده است.
# در اینجا برای کامل بودن، تابع main از پاسخ قبلی کپی می‌شود.

async def main():
    if not os.path.exists(URLS_FILE) or not os.path.exists(KEYWORDS_FILE):
        logging.critical("Input files not found.")
        return

    with open(URLS_FILE, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]
    with open(KEYWORDS_FILE, 'r', encoding='utf-8') as f:
<<<<<<< HEAD
        categories_data = json.load(f)
=======
        categories_data = json.load(f) # categories_data حاوی کل محتوای keywords.json است
>>>>>>> 80b6e0fbf644d44f4576259ce2a8e0a0d617b228

    protocol_patterns_for_matching = {
        cat: patterns for cat, patterns in categories_data.items() if cat in PROTOCOL_CATEGORIES
    }
    country_keywords_for_naming = {
        cat: patterns for cat, patterns in categories_data.items() if cat not in PROTOCOL_CATEGORIES
    }
    country_category_names = list(country_keywords_for_naming.keys())

    logging.info(f"Loaded {len(urls)} URLs and "
                 f"{len(categories_data)} total categories from keywords.json.")

    tasks = []
    sem = asyncio.Semaphore(CONCURRENT_REQUESTS)
    async def fetch_with_sem(session, url_to_fetch):
        async with sem:
            return await fetch_url(session, url_to_fetch)
    async with aiohttp.ClientSession() as session:
        fetched_pages = await asyncio.gather(*[fetch_with_sem(session, u) for u in urls])

    final_configs_by_country = {cat: set() for cat in country_category_names}
    final_all_protocols = {cat: set() for cat in PROTOCOL_CATEGORIES}

    logging.info("Processing pages for config name association...")
    for url, text in fetched_pages:
        if not text:
            continue

        page_protocol_matches = find_matches(text, protocol_patterns_for_matching)
        all_page_configs_after_filter = set()
        for protocol_cat_name, configs_found in page_protocol_matches.items():
            if protocol_cat_name in PROTOCOL_CATEGORIES:
                for config in configs_found:
                    if should_filter_config(config):
                        continue
                    all_page_configs_after_filter.add(config)
                    final_all_protocols[protocol_cat_name].add(config)

        for config in all_page_configs_after_filter:
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
            
            current_name_to_check_str = name_to_check if isinstance(name_to_check, str) else ""

            for country_name_key, keywords_for_country_list in country_keywords_for_naming.items():
                text_keywords_for_country = []
                if isinstance(keywords_for_country_list, list):
                    for kw in keywords_for_country_list:
<<<<<<< HEAD
                        if isinstance(kw, str):
                            # این بخش برای پیدا کردن کانفیگ‌هاست، نه نمایش نام در ریدمی
                            # پس ایموجی و نام فارسی را نباید به عنوان کلیدواژه جستجو استفاده کرد اگر هدف فقط تطبیق نام انگلیسی یا کد است
                            # با این حال، منطق فعلی شما ممکن است روی نام فارسی هم تطبیق دهد اگر در اسم کانفیگ باشد
                            # فعلا این بخش را بدون تغییر زیاد رها می‌کنیم، تمرکز روی نمایش در ریدمی است
                            is_potential_emoji_or_short_code = (1 <= len(kw) <= 7)
                            is_alphanumeric = kw.isalnum()
                            if not (is_potential_emoji_or_short_code and not is_alphanumeric): # اگر ایموجی نیست
                                if not is_persian_like(kw): # اگر فارسی هم نیست
                                     text_keywords_for_country.append(kw)
                                elif kw.lower() == country_name_key.lower(): # اگر نام فارسی با کلید اصلی یکی است (بعید)
                                    text_keywords_for_country.append(kw)
=======
                        # اینجا فرض می‌کنیم که اگر آیتم کوتاه باشد و فقط شامل حروف و اعداد نباشد، ممکن است ایموجی باشد و نباید در جستجوی متنی استفاده شود.
                        # اگر آیتم طولانی‌تر باشد یا فقط شامل حروف و اعداد باشد، به عنوان کلیدواژه متنی در نظر گرفته می‌شود.
                        if isinstance(kw, str):
                            is_potential_emoji_or_short_code = (1 <= len(kw) <= 7)
                            is_alphanumeric = kw.isalnum()
                            # اگر کوتاه است و alphanumeric نیست (مثل 🇦🇫) یا اگر alphanumeric است ولی طولش بیشتر از ۳ است (مثل Afghanistan)
                            # یا اگر alphanumeric نیست و طولش بیشتر از ۳ است (بعید برای کلیدواژه کشور)
                            # هدف این است که کدهای دوحرفی و نام‌های کامل کشور را نگه داریم ولی ایموجی‌ها را برای جستجوی متن حذف کنیم.
                            if not (is_potential_emoji_or_short_code and not is_alphanumeric): # اگر ایموجی نیست، اضافه کن
                                text_keywords_for_country.append(kw)
>>>>>>> 80b6e0fbf644d44f4576259ce2a8e0a0d617b228


                for keyword in text_keywords_for_country:
                    match_found = False
                    is_abbr = (len(keyword) == 2 or len(keyword) == 3) and re.match(r'^[A-Z]+$', keyword)
                    
                    if is_abbr:
                        pattern = r'\b' + re.escape(keyword) + r'\b'
                        if re.search(pattern, current_name_to_check_str, re.IGNORECASE):
                            match_found = True
                    else:
                        if keyword.lower() in current_name_to_check_str.lower():
                            match_found = True
                    
                    if match_found:
                        final_configs_by_country[country_name_key].add(config)
                        break 
                if match_found: break

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
    
    generate_simple_readme(protocol_counts, country_counts, categories_data, 
<<<<<<< HEAD
                           github_repo_path="10ium/ScrapeAndCategorize",
                           github_branch="main")
=======
                           github_repo_path="10ium/ScrapeAndCategorize", # مسیر ریپازیتوری خودتان
                           github_branch="main") # نام برنچ اصلی شما
>>>>>>> 80b6e0fbf644d44f4576259ce2a8e0a0d617b228

    logging.info("--- Script Finished ---")

if __name__ == "__main__":
    asyncio.run(main())
