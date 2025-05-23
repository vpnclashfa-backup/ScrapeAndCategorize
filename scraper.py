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
from urllib.parse import parse_qs, unquote # <--- unquote اضافه شد

# --- Configuration ---
URLS_FILE = 'urls.txt'
KEYWORDS_FILE = 'keywords.json'
OUTPUT_DIR = 'output_configs'
README_FILE = 'README.md'
REQUEST_TIMEOUT = 15  # seconds
CONCURRENT_REQUESTS = 10  # Max concurrent requests

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
    """
    Decodes a Base64 string, handling URL-safe and padding issues.
    Tries URL-safe first, then standard. Returns None on error.
    """
    try:
        data = data.replace('_', '/').replace('-', '+') # Ensure standard alphabet
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8')
    except Exception as e:
        # logging.debug(f"Base64 decode failed for '{data[:20]}...': {e}")
        return None

# --- Protocol Name Extraction Helpers ---
def get_vmess_name(vmess_link):
    """Extracts the name (ps) from a Vmess link if possible."""
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
    """Extracts the name (remarks) from an SSR link if possible."""
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
            return decode_base64(remarks_b64) # Remarks is also Base64
    except Exception as e:
        logging.warning(f"Failed to parse SSR name from {ssr_link[:30]}...: {e}")
    return None

async def fetch_url(session, url):
    """Asynchronously fetches the content of a single URL."""
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

def find_matches(text, categories):
    """Finds all matches using keywords.json patterns."""
    matches = {category: set() for category in categories}
    for category, patterns in categories.items():
        for pattern_str in patterns:
            try:
                pattern = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
                found = pattern.findall(text)
                if found:
                    cleaned_found = {item.strip() for item in found if item.strip()}
                    matches[category].update(cleaned_found)
            except re.error as e:
                logging.error(f"Regex error for '{pattern_str}': {e}")
    return {k: v for k, v in matches.items() if v}

def save_to_file(directory, category_name, items_set):
    """Helper function to save a set to a file and return count."""
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

def generate_simple_readme(protocol_counts, country_counts):
    """Generates a simpler README.md content."""
    tz = pytz.timezone('Asia/Tehran')
    now = datetime.now(tz)
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S %Z")

    md_content = f"# 📊 نتایج استخراج (آخرین به‌روزرسانی: {timestamp})\n\n"
    md_content += "این فایل به صورت خودکار ایجاد شده است.\n\n"
    md_content += "**توضیح:** فایل‌های کشورها فقط شامل کانفیگ‌هایی هستند که نام/پرچم کشور (با رعایت مرز کلمه برای مخفف‌ها) در **اسم کانفیگ** پیدا شده باشد. اسم کانفیگ ابتدا از بخش `#` لینک و در صورت نبود، از نام داخلی (برای Vmess/SSR) استخراج می‌شود.\n\n"
    md_content += "**نکته:** کانفیگ‌هایی که به شدت URL-Encode شده‌اند (حاوی `%25%25%25` یا `I_Love_`) از نتایج حذف شده‌اند.\n\n" # <--- اضافه شد

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
    """Main function to coordinate the scraping process."""
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

    # --- Fetch URLs ---
    tasks = []
    sem = asyncio.Semaphore(CONCURRENT_REQUESTS)
    async def fetch_with_sem(session, url):
        async with sem:
            return await fetch_url(session, url)
    async with aiohttp.ClientSession() as session:
        fetched_pages = await asyncio.gather(*[fetch_with_sem(session, url) for url in urls])

    # --- Process & Aggregate ---
    final_configs_by_country = {cat: set() for cat in country_category_names}
    final_all_protocols = {cat: set() for cat in PROTOCOL_CATEGORIES}

    # <<<--- اضافه شد: الگوی فیلتر کردن --- >>>
    filter_pattern = re.compile(r'(%25){3,}') # شناسایی ۳ یا بیشتر %25 پشت سر هم
    # <<<--- پایان بخش اضافه شده --- >>>

    logging.info("Processing pages for config name association...")
    for url, text in fetched_pages:
        if not text:
            continue

        page_matches = find_matches(text, categories)

        all_page_configs = set()
        for cat in PROTOCOL_CATEGORIES:
            if cat in page_matches:
                # <<<--- تغییر مهم: اعمال فیلتر --- >>>
                for config in page_matches[cat]:
                    # اگر کانفیگ با الگوی فیلتر مطابقت داشت یا حاوی I_Love_ بود، آن را نادیده بگیر
                    if filter_pattern.search(config) or 'I_Love_' in config:
                        logging.warning(f"Skipping heavily encoded/filtered config: {config[:60]}...")
                        continue # برو سراغ کانفیگ بعدی و این یکی را اضافه نکن

                    # اگر فیلتر نشد، آن را اضافه کن
                    all_page_configs.add(config)
                    final_all_protocols[cat].add(config)
                # <<<--- پایان تغییر مهم --- >>>


        # حالا با all_page_configs که فیلتر شده است، کار می‌کنیم
        for config in all_page_configs:
            name_to_check = None

            # 1. اولویت با نام بعد از #
            if '#' in config:
                try:
                    potential_name = config.split('#', 1)[1]
                    name_to_check = unquote(potential_name).strip()
                    if not name_to_check:
                        name_to_check = None
                except IndexError:
                    pass

            # 2. اگر نام # نبود، نام داخلی را چک کن
            if not name_to_check:
                if config.startswith('ssr://'):
                    name_to_check = get_ssr_name(config)
                elif config.startswith('vmess://'):
                    name_to_check = get_vmess_name(config)

            # 3. اگر نامی پیدا نشد، برو بعدی
            if not name_to_check:
                continue

            # 4. بررسی کشور با نام پیدا شده
            for country, keywords in country_categories.items():
                for keyword in keywords:
                    match_found = False
                    is_abbr = (len(keyword) == 2 or len(keyword) == 3) and re.match(r'^[A-Z]+$', keyword)

                    if is_abbr:
                        pattern = r'\b' + re.escape(keyword) + r'\b'
                        if re.search(pattern, name_to_check, re.IGNORECASE):
                            match_found = True
                    else:
                        if keyword.lower() in name_to_check.lower():
                            match_found = True

                    if match_found:
                        final_configs_by_country[country].add(config)
                        break
                if match_found:
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

    # --- Generate README.md ---
    generate_simple_readme(protocol_counts, country_counts)

    logging.info("--- Script Finished ---")

if __name__ == "__main__":
    asyncio.run(main())
