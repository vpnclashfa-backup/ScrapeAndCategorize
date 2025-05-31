import asyncio
import aiohttp
import json
import re
import logging
from bs4 import BeautifulSoup
import os
import shutil
from datetime import datetime
import pytz # اطمینان حاصل کنید که pytz نصب شده: pip install pytz
import base64
from urllib.parse import parse_qs, unquote

# --- Configuration ---
URLS_FILE = 'urls.txt'
KEYWORDS_FILE = 'keywords.json' # این فایل باید حاوی پرچم‌ها باشد
OUTPUT_DIR = 'output_configs'
README_FILE = 'README.md'
REQUEST_TIMEOUT = 15  # seconds
CONCURRENT_REQUESTS = 10  # Max concurrent requests
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

def find_matches(text, categories_data): # نام پارامتر به categories_data تغییر کرد
    matches = {category: set() for category in categories_data}
    for category, patterns in categories_data.items():
        for pattern_str in patterns:
            # اگر لیست الگوها خالی باشد یا آیتم‌ها رشته نباشند (مثلاً در مورد پرچم‌ها)
            if not isinstance(pattern_str, str):
                continue
            try:
                # برای پروتکل‌ها، الگوها رجکس هستند. برای کشورها، کلمات کلیدی هستند (به جز پرچم).
                # این تابع صرفاً برای پیدا کردن کانفیگ‌ها با رجکس پروتکل‌ها استفاده می‌شود.
                # بنابراین، تنها زمانی که pattern_str یک رجکس معتبر است، باید کامپایل شود.
                # فرض می‌کنیم الگوهای پروتکل‌ها همیشه معتبرند.
                is_protocol_pattern = any(proto_prefix in pattern_str for proto_prefix in [p.lower() + "://" for p in PROTOCOL_CATEGORIES])

                if category in PROTOCOL_CATEGORIES or is_protocol_pattern: # فقط برای پروتکل‌ها رجکس را اعمال کن
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

# --- تابع اصلاح شده generate_simple_readme ---
def generate_simple_readme(protocol_counts, country_counts, all_keywords_data, github_repo_path="10ium/ScrapeAndCategorize", github_branch="main"):
    """Generates README.md with country flags and new GitHub raw link format."""
    tz = pytz.timezone('Asia/Tehran')
    now = datetime.now(tz)
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S %Z")

    # ساخت URL پایه برای لینک‌های خام GitHub
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
        md_content += "| کشور | تعداد کانفیگ مرتبط | لینک |\n"
        md_content += "|---|---|---|\n"
        for country_category_name, count in sorted(country_counts.items()):
            flag_emoji_str = ""
            # استخراج پرچم از all_keywords_data
            # country_category_name کلیدی مانند "USA", "Afghanistan" و غیره است.
            if country_category_name in all_keywords_data:
                keywords_list = all_keywords_data[country_category_name]
                if keywords_list and isinstance(keywords_list, list): # اطمینان از اینکه لیست است و خالی نیست
                    # فرض بر این است که آخرین آیتم در لیست کلیدواژه‌ها برای دسته‌بندی کشور، ایموجی پرچم آن است.
                    potential_flag = keywords_list[-1]
                    # یک بررسی ساده: آیا یک رشته کوتاه است و احتمالاً یک ایموجی است.
                    # برای اطمینان بیشتر می‌توان بررسی کرد که آیا این کاراکترها در محدوده ایموجی‌های پرچم هستند یا خیر.
                    # با توجه به ساختار JSON شما، آخرین آیتم پرچم است.
                    if isinstance(potential_flag, str) and len(potential_flag) < 5: # پرچم‌ها معمولا کوتاه هستند
                        flag_emoji_str = potential_flag + " " # اضافه کردن یک فاصله بعد از پرچم

            file_link = f"{raw_github_base_url}/{country_category_name}.txt"
            link_text = f"{flag_emoji_str}{country_category_name}.txt" # اضافه کردن پرچم به متن لینک
            md_content += f"| {country_category_name} | {count} | [`{link_text}`]({file_link}) |\n"
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
        # نام متغیر categories حفظ شده چون در بقیه اسکریپت استفاده می‌شود.
        # این متغیر حاوی تمام داده‌های keywords.json خواهد بود.
        categories_data = json.load(f)

    # جداسازی دسته‌بندی کشورها از پروتکل‌ها
    # categories_data شامل هم کشورها و هم پروتکل‌ها است
    # find_matches برای پیدا کردن لینک‌های کانفیگ از روی رجکس‌های پروتکل‌ها استفاده می‌کند.
    # دسته‌بندی کشورها برای تطبیق نام کانفیگ با کلمات کلیدی کشورها استفاده می‌شود.

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

        # پیدا کردن تمام کانفیگ‌های پروتکل‌ها در صفحه فعلی با استفاده از رجکس‌ها
        page_protocol_matches = find_matches(text, protocol_patterns_for_matching)

        all_page_configs_after_filter = set()
        for protocol_cat_name, configs_found in page_protocol_matches.items():
            if protocol_cat_name in PROTOCOL_CATEGORIES: # اطمینان از اینکه یک دسته پروتکل است
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

            for country_name_key, keywords_for_country in country_keywords_for_naming.items():
                # keywords_for_country شامل نام‌ها، کدها و پرچم است. پرچم نباید برای تطبیق نام استفاده شود.
                # ما فقط کلمات کلیدی متنی را برای تطبیق نیاز داریم.
                text_keywords_for_country = [kw for kw in keywords_for_country if isinstance(kw, str) and not (len(kw) < 5 and not kw.isalnum())] # فیلتر کردن پرچم‌ها

                for keyword in text_keywords_for_country:
                    match_found = False
                    is_abbr = (len(keyword) == 2 or len(keyword) == 3) and re.match(r'^[A-Z]+$', keyword)
                    
                    # اطمینان از اینکه name_to_check رشته است
                    current_name_to_check = name_to_check if isinstance(name_to_check, str) else ""

                    if is_abbr:
                        pattern = r'\b' + re.escape(keyword) + r'\b'
                        if re.search(pattern, current_name_to_check, re.IGNORECASE):
                            match_found = True
                    else:
                        if keyword.lower() in current_name_to_check.lower():
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
    
    # --- فراخوانی تابع generate_simple_readme با پارامتر جدید ---
    # categories_data حاوی تمام داده‌های keywords.json است که شامل پرچم‌ها نیز می‌شود.
    # می‌توانید مسیر ریپازیتوری و نام برنچ را در صورت نیاز تغییر دهید
    generate_simple_readme(protocol_counts, country_counts, categories_data, 
                           github_repo_path="10ium/ScrapeAndCategorize",  # مسیر ریپازیتوری خودتان
                           github_branch="main") # نام برنچ اصلی شما

    logging.info("--- Script Finished ---")

if __name__ == "__main__":
    asyncio.run(main())
