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
import time # برای لاگ‌های زمان‌بندی که در پاسخ قبلی پیشنهاد شد (اختیاری)

# --- Configuration ---
URLS_FILE = 'urls.txt'
KEYWORDS_FILE = 'keywords.json'
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

DEFAULT_FLAG = "🏳️"

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
        logging.debug(f"Failed to parse Vmess name from {vmess_link[:30]}...: {e}") # Debug level for less noise
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
        logging.debug(f"Failed to parse SSR name from {ssr_link[:30]}...: {e}") # Debug level
    return None

# --- Filter Function (با پارامتر source_url) ---
def should_filter_config(config, source_url="Unknown source"): # <--- پارامتر source_url اضافه شد
    """
    Checks if a config should be filtered based on heavy encoding,
    specific keywords, or excessive length. Logs the source URL if filtered.
    """
    # 1. Check for specific keywords (case-insensitive)
    if 'i_love_' in config.lower():
        logging.warning(f"Filtering by keyword 'I_Love_' from {source_url}: {config[:60]}...") # <--- source_url اضافه شد
        return True

    # 2. Check for high count of '%25'
    percent25_count = config.count('%25')
    if percent25_count >= MIN_PERCENT25_COUNT:
        logging.warning(f"Filtering by high %25 count ({percent25_count}) from {source_url}: {config[:60]}...") # <--- source_url اضافه شد
        return True

    # 3. Check for excessive length
    if len(config) >= MAX_CONFIG_LENGTH:
        logging.warning(f"Filtering by excessive length ({len(config)}) from {source_url}: {config[:60]}...") # <--- source_url اضافه شد
        return True

    # 4. Check for '%2525' as another indicator
    if '%2525' in config:
        logging.warning(f"Filtering by '%2525' presence from {source_url}: {config[:60]}...") # <--- source_url اضافه شد
        return True

    return False

async def fetch_url(session, url):
    """Asynchronously fetches the content of a single URL."""
    try:
        async with session.get(url, timeout=REQUEST_TIMEOUT) as response:
            response.raise_for_status()
            html = await response.text()
            soup = BeautifulSoup(html, 'html.parser')
            text_content = ""
            # استخراج متن از تگ‌های رایج‌تر و همچنین div و span و td
            for element in soup.find_all(['pre', 'code', 'p', 'div', 'li', 'span', 'td', 'article', 'section']):
                text_content += element.get_text(separator='\n', strip=True) + "\n"
            if not text_content.strip(): # اگر متن استخراج شده از تگ‌های خاص خالی بود
                text_content = soup.get_text(separator=' ', strip=True) # متن کلی صفحه را بگیر

            logging.info(f"Successfully fetched: {url}")
            return url, text_content
    except asyncio.TimeoutError:
        logging.warning(f"Timeout while fetching {url} after {REQUEST_TIMEOUT} seconds.")
        return url, None
    except aiohttp.ClientError as e:
        logging.warning(f"ClientError while fetching {url}: {e}")
        return url, None
    except Exception as e:
        logging.warning(f"Failed to fetch or process {url}: {e}")
        return url, None

def find_matches(text, categories_with_patterns):
    matches = {category: set() for category in categories_with_patterns}
    for category, patterns in categories_with_patterns.items():
        for pattern_str in patterns:
            # جلوگیری از استفاده از خود ایموجی پرچم به عنوان الگوی regex
            if len(pattern_str) < 5 and any(0x1F1E6 <= ord(char) <= 0x1F1FF for char in pattern_str): # Heuristic for regional indicators
                 continue 

            try:
                if category in PROTOCOL_CATEGORIES: # فقط برای پروتکل‌ها از regex استفاده شود
                    pattern = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
                    found = pattern.findall(text)
                    if found:
                        cleaned_found = {item.strip() for item in found if item.strip()}
                        matches[category].update(cleaned_found)
            except re.error as e:
                logging.error(f"Regex error for pattern '{pattern_str}' in category '{category}': {e}")
    return {k: v for k, v in matches.items() if v}


def save_to_file(directory, category_name, items_set):
    if not items_set:
        return False, 0
    file_path = os.path.join(directory, f"{category_name}.txt")
    count = len(items_set)
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            for item in sorted(list(items_set)): # مرتب‌سازی برای خروجی یکنواخت
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

    github_repository = os.environ.get('GITHUB_REPOSITORY')
    github_ref_name = os.environ.get('GITHUB_REF_NAME')

    base_url_for_link = ""
    if github_repository and github_ref_name:
        base_url_for_link = f"https://raw.githubusercontent.com/{github_repository}/{github_ref_name}"

    md_content += "## 📁 فایل‌های پروتکل‌ها\n\n"
    if protocol_counts:
        md_content += "| پروتکل | تعداد کل | لینک |\n"
        md_content += "|---|---|---|\n"
        for category, count in sorted(protocol_counts.items()):
            file_name_display = f"{category}.txt"
            file_path_in_repo = f"{OUTPUT_DIR}/{category}.txt"
            link_url = f"./{file_path_in_repo}" # پیش‌فرض لینک نسبی
            if base_url_for_link:
                link_url = f"{base_url_for_link}/{file_path_in_repo}"
            md_content += f"| {category} | {count} | [`{file_name_display}`]({link_url}) |\n"
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
            file_path_in_repo = f"{OUTPUT_DIR}/{category}.txt"
            link_url = f"./{file_path_in_repo}" # پیش‌فرض لینک نسبی
            if base_url_for_link:
                link_url = f"{base_url_for_link}/{file_path_in_repo}"
            md_content += f"| {flag_emoji} | {category} | {count} | [`{file_name_display}`]({link_url}) |\n"
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
    overall_start_time = time.time() # برای لاگ زمان کل
    logging.info("--- Script Started ---")

    if not os.path.exists(URLS_FILE) or not os.path.exists(KEYWORDS_FILE):
        logging.critical(f"Input files not found. Ensure {URLS_FILE} and {KEYWORDS_FILE} exist.")
        return

    with open(URLS_FILE, 'r', encoding='utf-8') as f: # اضافه کردن encoding='utf-8'
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')] # نادیده گرفتن خطوط کامنت شده
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
                # یک بررسی ساده برای اینکه آیا آخرین آیتم شبیه پرچم است
                is_likely_flag = (len(potential_flag) == 2 and all(0x1F1E6 <= ord(char) <= 0x1F1FF for char in potential_flag)) or \
                                 (len(potential_flag) == 1 and ord(potential_flag) > 255 and potential_flag not in ['中国', '日本', '韓国']) # اضافه کردن یک استثنا ساده برای پرچم‌های تک کاراکتری غیرمعمول در این زمینه

                if is_likely_flag:
                    country_flags_from_keywords[category_name] = potential_flag
                    if len(keywords_or_patterns_list) > 1:
                        country_keywords_map[category_name] = keywords_or_patterns_list[:-1]
                    else: # اگر فقط پرچم بود، نام دسته را به عنوان کلمه کلیدی اضافه کن
                        country_keywords_map[category_name] = [category_name]
                else:
                    country_keywords_map[category_name] = keywords_or_patterns_list
            else:
                 country_keywords_map[category_name] = [category_name]


    country_category_names = list(country_keywords_map.keys())

    logging.info(f"Loaded {len(urls)} URLs and {len(all_categories_data)} categories.")
    # logging.debug(f"Protocol categories patterns: {patterns_for_protocols}")
    # logging.debug(f"Country keywords map: {country_keywords_map}")
    # logging.debug(f"Extracted country flags: {country_flags_from_keywords}")


    logging.info("Starting URL fetching...")
    fetch_start_time = time.time()
    sem = asyncio.Semaphore(CONCURRENT_REQUESTS)
    async def fetch_with_sem(session, url_item): # تغییر نام پارامتر برای وضوح
        async with sem:
            return await fetch_url(session, url_item) # ارسال url_item
    async with aiohttp.ClientSession() as session:
        fetched_pages = await asyncio.gather(*[fetch_with_sem(session, u) for u in urls]) # استفاده از u
    logging.info(f"URL fetching finished in {time.time() - fetch_start_time:.2f} seconds. Fetched {len([p for p in fetched_pages if p[1] is not None])}/{len(urls)} pages successfully.")


    final_configs_by_country = {cat: set() for cat in country_category_names}
    final_all_protocols = {cat: set() for cat in PROTOCOL_CATEGORIES}


    logging.info("Processing pages for config extraction and name association...")
    process_start_time = time.time()
    unique_configs_overall = set() # برای جلوگیری از پردازش چندباره یک کانفیگ اگر در صفحات مختلف تکرار شود

    for url_source, text_content in fetched_pages: # تغییر نام متغیرها برای وضوح
        if not text_content:
            continue

        page_protocol_matches = find_matches(text_content, patterns_for_protocols)

        current_page_configs_unfiltered = set()
        for protocol_cat, configs_found in page_protocol_matches.items():
            for config in configs_found:
                current_page_configs_unfiltered.add(config) # همه کانفیگ‌های پیدا شده در صفحه، قبل از فیلتر کلی

        # فیلتر کردن و اضافه کردن به لیست‌های نهایی پروتکل‌ها
        for config in current_page_configs_unfiltered:
            if config in unique_configs_overall: # اگر این کانفیگ قبلا پردازش شده، از آن بگذر
                continue
            
            # <--- فراخوانی should_filter_config با url_source --- >
            if should_filter_config(config, url_source):
                unique_configs_overall.add(config) # اضافه به دیده شده‌ها تا دوباره لاگ نشود اگر تکراری بود
                continue
            
            unique_configs_overall.add(config) # اضافه به مجموعه کلی کانفیگ‌های دیده شده (فیلتر نشده)
            
            # اضافه کردن به final_all_protocols بر اساس نوع پروتکل استخراج شده از find_matches
            # برای این کار باید بدانیم این config خاص از کدام protocol_cat در find_matches آمده است.
            # راه ساده‌تر: پس از فیلتر، نوع پروتکل را دوباره تشخیص دهیم یا find_matches را طوری تغییر دهیم که نوع را هم برگرداند.
            # برای سادگی فعلی، فرض می‌کنیم که اگر کانفیگی از find_matches آمده، نوع آن مشخص است.
            # این بخش نیاز به بازنگری دارد اگر یک کانفیگ می‌تواند توسط چندین پترن پروتکل مچ شود.
            # فرض فعلی: هر کانفیگ متعلق به یک پروتکل است که find_matches آن را پیدا کرده.

            # برای افزودن صحیح به final_all_protocols، باید بدانیم این config از کدام دسته پروتکل است.
            # می‌توانیم این اطلاعات را از page_protocol_matches استخراج کنیم.
            config_protocol_origin = None
            for p_cat, p_configs in page_protocol_matches.items():
                if config in p_configs:
                    config_protocol_origin = p_cat
                    break
            
            if config_protocol_origin and config_protocol_origin in final_all_protocols:
                 final_all_protocols[config_protocol_origin].add(config)


            # تطبیق با کشورها
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
                # می‌توان برای سایر پروتکل‌ها نیز تابع استخراج نام مشابه اضافه کرد

            if not name_to_check:
                # اگر نامی برای بررسی کشور وجود ندارد، این کانفیگ به هیچ کشوری مرتبط نمی‌شود
                # اما همچنان در لیست پروتکل مربوطه‌اش (اگر نوعش مشخص باشد) باقی می‌ماند
                continue


            # بررسی کشور با نام پیدا شده
            country_match_for_this_config = False
            for country_name, keywords_for_country in country_keywords_map.items():
                for keyword in keywords_for_country:
                    if not keyword.strip(): continue # نادیده گرفتن کلمات کلیدی خالی

                    match_found_for_keyword = False
                    # بررسی مخفف‌ها با مرز کلمه
                    # کلمات کلیدی که ۲ یا ۳ حرفی و همگی بزرگ هستند را مخفف در نظر می‌گیریم
                    is_abbr = (len(keyword) == 2 or len(keyword) == 3) and keyword.isupper()

                    try:
                        if is_abbr:
                            # برای مخفف‌ها، جستجو با مرز کلمه (\b) انجام می‌شود
                            pattern_abbr = r'\b' + re.escape(keyword) + r'\b'
                            if re.search(pattern_abbr, name_to_check, re.IGNORECASE):
                                match_found_for_keyword = True
                        else:
                            # برای کلمات کلیدی طولانی‌تر، جستجوی ساده‌تر (بدون مرز کلمه اجباری در ابتدا)
                            # اما می‌توان مرز کلمه را هم برای دقت بیشتر اضافه کرد
                            pattern_keyword = r'(?i)\b' + re.escape(keyword) + r'\b' # جستجوی case-insensitive با مرز کلمه
                            if re.search(pattern_keyword, name_to_check):
                                match_found_for_keyword = True
                            elif keyword.lower() in name_to_check.lower(): # حالت پشتیبان بدون مرز کلمه
                                match_found_for_keyword = True


                    except re.error as e:
                        logging.error(f"Regex error during country keyword matching for keyword '{keyword}' in name '{name_to_check}': {e}")
                        continue # برو به کلمه کلیدی بعدی

                    if match_found_for_keyword:
                        final_configs_by_country[country_name].add(config)
                        country_match_for_this_config = True # برای این کانفیگ یک کشور پیدا شد
                        break # شکستن حلقه کلمات کلیدی این کشور
                
                if country_match_for_this_config:
                    break # شکستن حلقه کشورها، چون اولین تطابق کافی است

    logging.info(f"Processing and aggregation finished in {time.time() - process_start_time:.2f} seconds.")
    logging.info(f"Total unique configs found before country association: {len(unique_configs_overall)}")


    # --- Save Output Files ---
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

    logging.info("Generating README...")
    readme_start_time = time.time()
    generate_simple_readme(protocol_counts, country_counts, country_flags_from_keywords)
    logging.info(f"README generation finished in {time.time() - readme_start_time:.2f} seconds.")

    logging.info(f"--- Script Finished in {time.time() - overall_start_time:.2f} seconds ---")

if __name__ == "__main__":
    asyncio.run(main())
