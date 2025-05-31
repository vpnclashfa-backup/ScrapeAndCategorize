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
import time

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
logging.basicConfig(level=logging.INFO, # برای دیدن تمام لاگ‌های پیشنهادی، سطح INFO مناسب است
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
    if not vmess_link.startswith("vmess://"): return None
    try:
        b64_part = vmess_link[8:]
        decoded_str = decode_base64(b64_part)
        if decoded_str:
            vmess_json = json.loads(decoded_str)
            return vmess_json.get('ps')
    except Exception as e:
        logging.debug(f"Failed to parse Vmess name from {vmess_link[:30]}...: {e}")
    return None

def get_ssr_name(ssr_link):
    if not ssr_link.startswith("ssr://"): return None
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
        logging.debug(f"Failed to parse SSR name from {ssr_link[:30]}...: {e}")
    return None

# --- Filter Function ---
def should_filter_config(config, source_url="Unknown source"):
    if 'i_love_' in config.lower():
        logging.warning(f"Filtering by keyword 'I_Love_' from {source_url}: {config[:60]}...")
        return True
    percent25_count = config.count('%25')
    if percent25_count >= MIN_PERCENT25_COUNT:
        logging.warning(f"Filtering by high %25 count ({percent25_count}) from {source_url}: {config[:60]}...")
        return True
    if len(config) >= MAX_CONFIG_LENGTH:
        logging.warning(f"Filtering by excessive length ({len(config)}) from {source_url}: {config[:60]}...")
        return True
    if '%2525' in config:
        logging.warning(f"Filtering by '%2525' presence from {source_url}: {config[:60]}...")
        return True
    return False

async def fetch_url(session, url):
    try:
        async with session.get(url, timeout=REQUEST_TIMEOUT) as response:
            response.raise_for_status()
            html = await response.text() # خواندن کل محتوا
            # BeautifulSoup برای صفحات HTML پیچیده است، برای فایل‌های متنی ساده شاید لازم نباشد
            # اما برای یکنواختی و اگر برخی URLها ممکن است HTML باشند، نگه داشته شده
            soup = BeautifulSoup(html, 'html.parser')
            text_content = ""
            for element in soup.find_all(['pre', 'code', 'p', 'div', 'li', 'span', 'td', 'article', 'section', 'body']):
                text_content += element.get_text(separator='\n', strip=True) + "\n"
            if not text_content.strip():
                 # اگر از تگ‌های خاص چیزی نیامد، کل متن صفحه (حتی اگر HTML نباشد)
                 # اگر html خالی باشد، خود html را برمیگردانیم چون ممکن است فایل متنی باشد
                text_content = html if html else soup.get_text(separator=' ', strip=True)


            logging.info(f"Successfully fetched: {url} (Length: {len(text_content)})")
            return url, text_content
    except asyncio.TimeoutError:
        logging.warning(f"Timeout while fetching {url} after {REQUEST_TIMEOUT} seconds.")
        return url, None
    except aiohttp.ClientError as e:
        logging.warning(f"ClientError for {url}: {e}")
        return url, None
    except Exception as e:
        logging.warning(f"General failure to fetch or process {url}: {e}")
        return url, None

def find_matches(text, categories_with_patterns):
    matches = {category: set() for category in categories_with_patterns}
    if not text: # اگر متن ورودی خالی است
        return matches
        
    for category, patterns in categories_with_patterns.items():
        for pattern_str in patterns:
            if len(pattern_str) < 5 and any(0x1F1E6 <= ord(char) <= 0x1F1FF for char in pattern_str):
                 continue
            try:
                if category in PROTOCOL_CATEGORIES:
                    # کامپایل کردن Regex برای هر جستجو می‌تواند کند باشد اگر تعداد پترن‌ها زیاد است
                    # اما اینجا تعداد پروتکل‌ها کم است، پس قابل قبول است
                    pattern = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
                    found = pattern.findall(text)
                    if found:
                        cleaned_found = {item.strip() for item in found if item.strip()}
                        matches[category].update(cleaned_found)
            except re.error as e:
                logging.error(f"Regex error for pattern '{pattern_str}' in category '{category}': {e}")
    return {k: v for k, v in matches.items() if v}


def save_to_file(directory, category_name, items_set):
    if not items_set: return False, 0
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

    github_repository = os.environ.get('GITHUB_REPOSITORY')
    github_ref_name = os.environ.get('GITHUB_REF_NAME')
    base_url_for_link = ""
    if github_repository and github_ref_name:
        base_url_for_link = f"https://raw.githubusercontent.com/{github_repository}/{github_ref_name}"

    md_content += "## 📁 فایل‌های پروتکل‌ها\n\n"
    if protocol_counts:
        md_content += "| پروتکل | تعداد کل | لینک |\n|---|---|---|\n"
        for category, count in sorted(protocol_counts.items()):
            file_name_display = f"{category}.txt"
            file_path_in_repo = f"{OUTPUT_DIR}/{category}.txt"
            link_url = f"./{file_path_in_repo}"
            if base_url_for_link: link_url = f"{base_url_for_link}/{file_path_in_repo}"
            md_content += f"| {category} | {count} | [`{file_name_display}`]({link_url}) |\n"
    else: md_content += "هیچ کانفیگ پروتکلی یافت نشد.\n"
    md_content += "\n## 🌍 فایل‌های کشورها (حاوی کانفیگ)\n\n"
    if country_counts:
        md_content += "| پرچم | کشور | تعداد کانفیگ مرتبط | لینک |\n|:---:|---|---|---|\n"
        for category, count in sorted(country_counts.items()):
            flag_emoji = country_flags_map.get(category, DEFAULT_FLAG)
            file_name_display = f"{category}.txt"
            file_path_in_repo = f"{OUTPUT_DIR}/{category}.txt"
            link_url = f"./{file_path_in_repo}"
            if base_url_for_link: link_url = f"{base_url_for_link}/{file_path_in_repo}"
            md_content += f"| {flag_emoji} | {category} | {count} | [`{file_name_display}`]({link_url}) |\n"
    else: md_content += "هیچ کانفیگ مرتبط با کشوری یافت نشد.\n"
    md_content += "\n"
    try:
        with open(README_FILE, 'w', encoding='utf-8') as f: f.write(md_content)
        logging.info(f"Successfully generated {README_FILE}")
    except Exception as e: logging.error(f"Failed to write {README_FILE}: {e}")

async def main():
    overall_start_time = time.time()
    logging.info("--- Script Started ---")

    if not os.path.exists(URLS_FILE) or not os.path.exists(KEYWORDS_FILE):
        logging.critical(f"Input files {URLS_FILE} or {KEYWORDS_FILE} not found.")
        return

    try:
        with open(URLS_FILE, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        with open(KEYWORDS_FILE, 'r', encoding='utf-8') as f:
            all_categories_data = json.load(f)
    except Exception as e:
        logging.critical(f"Error loading input files: {e}")
        return

    logging.info("Processing keywords.json...")
    keywords_setup_start_time = time.time()
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
                                 (len(potential_flag) == 1 and ord(potential_flag) > 255 and potential_flag not in ['中国', '日本', '韓国']) # Avoid misinterpreting CJK characters as flags
                if is_likely_flag:
                    country_flags_from_keywords[category_name] = potential_flag
                    country_keywords_map[category_name] = keywords_or_patterns_list[:-1] if len(keywords_or_patterns_list) > 1 else [category_name]
                else:
                    country_keywords_map[category_name] = list(keywords_or_patterns_list)
            else:
                 country_keywords_map[category_name] = [category_name]
    logging.info(f"keywords.json processing finished in {time.time() - keywords_setup_start_time:.2f} seconds.")

    country_category_names = list(country_keywords_map.keys())
    logging.info(f"Loaded {len(urls)} URLs and {len(all_categories_data)} categories.")

    # --- شمارنده برای کانفیگ‌های نادیده گرفته شده ---
    ignored_configs_count_by_source = {url: 0 for url in urls}


    logging.info("Starting URL fetching...")
    fetch_start_time = time.time()
    sem = asyncio.Semaphore(CONCURRENT_REQUESTS)
    async def fetch_with_sem(session, url_item):
        async with sem: return await fetch_url(session, url_item)
    async with aiohttp.ClientSession() as session:
        fetched_pages = await asyncio.gather(*[fetch_with_sem(session, u) for u in urls])
    successful_fetches = sum(1 for _, content in fetched_pages if content is not None)
    logging.info(f"URL fetching finished in {time.time() - fetch_start_time:.2f} seconds. Fetched {successful_fetches}/{len(urls)} pages successfully.")

    final_configs_by_country = {cat: set() for cat in country_category_names}
    final_all_protocols = {cat: set() for cat in PROTOCOL_CATEGORIES}
    unique_configs_overall = set()

    logging.info("Processing pages for config extraction and name association...")
    all_pages_processing_start_time = time.time()

    for i, (url_source, text_content) in enumerate(fetched_pages):
        page_process_start_time = time.time()
        logging.info(f"--- Processing page {i+1}/{len(urls)}: {url_source} ---")
        if not text_content:
            logging.info(f"Page {i+1} content is empty or fetch failed. Skipping.")
            continue
        logging.debug(f"Page {i+1} content length: {len(text_content)}")

        find_matches_start_time = time.time()
        page_protocol_matches = find_matches(text_content, patterns_for_protocols)
        num_potential_configs_on_page = sum(len(v) for v in page_protocol_matches.values())
        logging.info(f"Page {i+1}: find_matches finished in {time.time() - find_matches_start_time:.2f} seconds. Found {num_potential_configs_on_page} potential protocol configs.")

        configs_loop_start_time = time.time()
        num_passed_filter_on_page = 0
        num_added_to_country_on_page = 0

        current_page_unique_configs = set() # برای جلوگیری از پردازش تکراری کانفیگ در همین صفحه
        for protocol_cat, configs_found_for_protocol in page_protocol_matches.items():
            for config in configs_found_for_protocol:
                if config in current_page_unique_configs: # اگر در همین صفحه قبلا پردازش شده
                    continue
                current_page_unique_configs.add(config)

                if config in unique_configs_overall: # اگر در صفحات قبلی به عنوان یونیک (فیلترنشده یا فیلترشده) دیده شده
                    if should_filter_config(config, url_source): # فقط برای لاگ کردن و شمارش دوباره اگر فیلتر می‌شود
                         ignored_configs_count_by_source[url_source] +=1
                    continue # قبلا پردازش شده و به لیست‌های نهایی اضافه شده یا به عنوان فیلتر شده علامت خورده

                if should_filter_config(config, url_source):
                    ignored_configs_count_by_source[url_source] += 1
                    unique_configs_overall.add(config) # علامت‌گذاری به عنوان دیده شده (فیلتر شده)
                    continue
                
                unique_configs_overall.add(config) # علامت‌گذاری به عنوان دیده شده (فیلتر نشده)
                num_passed_filter_on_page += 1

                if protocol_cat in final_all_protocols:
                     final_all_protocols[protocol_cat].add(config)

                name_to_check = None
                if '#' in config:
                    try:
                        name_to_check = unquote(config.split('#', 1)[1]).strip()
                        if not name_to_check: name_to_check = None
                    except IndexError: pass
                if not name_to_check:
                    if config.startswith('ssr://'): name_to_check = get_ssr_name(config)
                    elif config.startswith('vmess://'): name_to_check = get_vmess_name(config)

                if not name_to_check: continue

                country_match_for_this_config = False
                for country_name, keywords_for_country in country_keywords_map.items():
                    for keyword in keywords_for_country:
                        if not keyword.strip(): continue
                        match_found_for_keyword = False
                        is_abbr = (len(keyword) == 2 or len(keyword) == 3) and keyword.isupper()
                        try:
                            if is_abbr:
                                if re.search(r'\b' + re.escape(keyword) + r'\b', name_to_check, re.IGNORECASE):
                                    match_found_for_keyword = True
                            else:
                                if re.search(r'(?i)\b' + re.escape(keyword) + r'\b', name_to_check) or keyword.lower() in name_to_check.lower():
                                    match_found_for_keyword = True
                        except re.error as e: logging.error(f"Regex error: keyword '{keyword}', name '{name_to_check}': {e}")
                        if match_found_for_keyword:
                            final_configs_by_country[country_name].add(config)
                            num_added_to_country_on_page +=1
                            country_match_for_this_config = True; break
                    if country_match_for_this_config: break
        
        logging.info(f"Page {i+1}: Config processing loop finished in {time.time() - configs_loop_start_time:.2f} sec. Configs passed filter: {num_passed_filter_on_page}. Added to country lists: {num_added_to_country_on_page}.")
        logging.info(f"--- Page {i+1} ({url_source}) total processing time: {time.time() - page_process_start_time:.2f} seconds ---")
    
    logging.info(f"ALL pages processing and aggregation finished in {time.time() - all_pages_processing_start_time:.2f} seconds.")
    logging.info(f"Total unique configs considered (passed filter or filtered): {len(unique_configs_overall)}")

    logging.info("--- Ignored Config Counts per Source ---")
    total_ignored_overall = 0
    for url_s, count in ignored_configs_count_by_source.items():
        if count > 0:
            logging.info(f"Source: {url_s} - Ignored configs: {count}")
            total_ignored_overall += count
    logging.info(f"Total ignored configs across all sources: {total_ignored_overall}")
    logging.info("----------------------------------------")

    if os.path.exists(OUTPUT_DIR): shutil.rmtree(OUTPUT_DIR)
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
