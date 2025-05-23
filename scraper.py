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

# <<<--- تابع اعتبارسنجی ساده شده --->>>
def is_config_valid(config_string, min_len=20, max_len=2500, max_overall_percent_char_ratio=0.5, max_specific_percent25_count=10):
    """
    Checks if a config string looks potentially valid.
    Focuses on length and extreme cases of URL encoding.
    """
    l = len(config_string)
    # 1. Check overall length
    if not (min_len <= l <= max_len):
        logging.warning(f"FILTER: REJECT (Length {l}): {config_string[:60]}...")
        return False

    # 2. Check for excessive overall '%' characters if the string is long enough
    if l > 50 and (config_string.count('%') / l) > max_overall_percent_char_ratio:
        logging.warning(f"FILTER: REJECT (High % Ratio): {config_string[:60]}...")
        return False

    # 3. Check for the specific problematic '%25' pattern if it's very frequent
    if config_string.count('%25') > max_specific_percent25_count:
        logging.warning(f"FILTER: REJECT (High %25 Count): {config_string[:60]}...")
        return False

    # 4. Must start with a known protocol (this is a basic sanity check)
    protocol_ok = False
    for p in PROTOCOL_CATEGORIES:
        if config_string.lower().startswith(p.lower() + "://"):
            protocol_ok = True
            break
    if not protocol_ok:
        logging.warning(f"FILTER: REJECT (No Valid Prefix): {config_string[:60]}...")
        return False

    logging.debug(f"FILTER: ACCEPT: {config_string[:60]}...")
    return True
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

def generate_simple_readme(protocol_counts, country_counts):
    tz = pytz.timezone('Asia/Tehran')
    now = datetime.now(tz)
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S %Z")

    md_content = f"# 📊 نتایج استخراج (آخرین به‌روزرسانی: {timestamp})\n\n"
    md_content += "این فایل به صورت خودکار ایجاد شده است.\n\n"
    md_content += "**توضیح:** فایل‌های کشورها فقط شامل کانفیگ‌هایی هستند که نام/پرچم کشور (با رعایت مرز کلمه برای مخفف‌ها) در **اسم خود کانفیگ (بعد از #)** پیدا شده باشد. کانفیگ‌های مشکوک (بسیار طولانی یا با کدگذاری شدید) فیلتر شده‌اند.\n\n" # <--- توضیح به‌روز شد

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
            if not is_config_valid(config):
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

    logging.info("--- Script Finished ---")

if __name__ == "__main__":
    asyncio.run(main())
