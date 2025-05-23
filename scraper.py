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

# <<<--- تابع اعتبارسنجی ساختاری به‌روز شده --->>>
def is_config_valid(config_string, min_len=30, max_len=2000, max_percent_25=5):
    """
    Checks if a config string has basic structural validity.
    """
    l = len(config_string)
    # 1. Check length
    if not (min_len <= l <= max_len):
        logging.debug(f"Skipping (Length {l}): {config_string[:30]}...")
        return False

    # 2. Check for excessive %25
    if config_string.count('%25') > max_percent_25:
        logging.debug(f"Skipping (%25 Count): {config_string[:60]}...")
        return False

    # 3. Must start with a known protocol
    proto_prefix = None
    for p in PROTOCOL_CATEGORIES:
        if config_string.lower().startswith(p.lower() + "://"):
            proto_prefix = p.lower()
            break
    if not proto_prefix:
        logging.debug(f"Skipping (No Prefix): {config_string[:30]}...")
        return False

    # 4. Must contain '@' (for most common structures)
    if '@' not in config_string:
        # Allow ssr and some ss without @, but be stricter otherwise
        if proto_prefix not in ['ssr', 'ss']:
            logging.debug(f"Skipping (No @): {config_string[:60]}...")
            return False

    # 5. Must contain a port number (almost always after @ or host)
    if not re.search(r':\d+', config_string):
        logging.debug(f"Skipping (No Port): {config_string[:60]}...")
        return False

    # 6. Check for a reasonable host (IP or domain)
    try:
        # Try to extract the part that should be the host
        host_part = re.split(r'[@:]', config_string.split('://', 1)[1])[1]
        host_part = host_part.split('?', 1)[0].split('#', 1)[0]
        if not host_part: # Host cannot be empty
            logging.debug(f"Skipping (Empty Host): {config_string[:60]}...")
            return False
        # Check if it looks like an IP or contains a dot (domain)
        if not (re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host_part) or '.' in host_part):
            logging.debug(f"Skipping (Invalid Host '{host_part}'): {config_string[:60]}...")
            return False
    except IndexError:
        logging.debug(f"Skipping (Host Parse Error): {config_string[:60]}...")
        return False # Couldn't parse likely host part

    # 7. Check for UUID in Vless/Vmess/Trojan
    if proto_prefix in ["vless", "vmess", "trojan"]:
        if not re.search(r'[a-fA-F0-9]{8}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{12}', config_string):
            logging.debug(f"Skipping (No UUID): {config_string[:60]}...")
            return False

    return True
# <<<--- پایان تابع اعتبارسنجی --->>>


async def fetch_url(session, url):
    """Asynchronously fetches the content of a single URL."""
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
    """Finds all matches using keywords.json patterns."""
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
    md_content += "**توضیح:** فایل‌های کشورها فقط شامل کانفیگ‌هایی هستند که نام/پرچم کشور (با رعایت مرز کلمه برای مخفف‌ها) در **اسم خود کانفیگ (بعد از #)** پیدا شده باشد. کانفیگ‌های فیک و نامعتبر از نظر ساختاری فیلتر شده‌اند.\n\n"

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

    logging.info("Processing pages & filtering configs...")
    for url, text in fetched_pages:
        if not text:
            continue

        page_matches = find_matches(text, categories)

        all_page_configs = set()
        for cat in PROTOCOL_CATEGORIES:
            if cat in page_matches:
                all_page_configs.update(page_matches[cat])

        # Filter and process valid configs
        for config in all_page_configs:
            # 1. Validate config structure
            if not is_config_valid(config):
                # logging.info(f"Skipping INVALID config: {config[:60]}...") # Keep logging level INFO
                continue # Skip if not valid

            # 2. Add to its protocol list
            for cat in PROTOCOL_CATEGORIES:
                if config.lower().startswith(cat.lower() + "://"):
                     final_all_protocols[cat].add(config)
                     break

            # 3. Associate with country if name matches
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

# --- Run the main function ---
if __name__ == "__main__":
    asyncio.run(main())
