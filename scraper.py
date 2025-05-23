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

# --- Protocol Categories (Ensure these match your keywords.json keys) ---
PROTOCOL_CATEGORIES = [
    "Vmess", "Vless", "Trojan", "ShadowSocks", "ShadowSocksR",
    "Tuic", "Hysteria2", "WireGuard" # Adjust if your keys are different (e.g., hy2)
]

async def fetch_url(session, url):
    """Fetches a single URL."""
    try:
        async with session.get(url, timeout=REQUEST_TIMEOUT) as response:
            response.raise_for_status()
            html = await response.text()
            soup = BeautifulSoup(html, 'html.parser')
            # Extract text, trying to preserve lines better
            text = '\n'.join(soup.stripped_strings)
            logging.info(f"Successfully fetched: {url}")
            return url, text
    except Exception as e:
        logging.warning(f"Failed to fetch or process {url}: {e}")
        return url, None

def compile_patterns(categories):
    """Compiles regex patterns for efficiency."""
    compiled = {}
    for category, patterns in categories.items():
        compiled[category] = [re.compile(p, re.IGNORECASE) for p in patterns]
    return compiled

def process_text_line_by_line(text, compiled_categories, protocol_categories):
    """Finds associations on a line-by-line basis."""
    country_categories = {k: v for k, v in compiled_categories.items() if k not in protocol_categories}
    protocol_patterns = {k: v for k, v in compiled_categories.items() if k in protocol_categories}

    associated_configs = {cat: set() for cat in country_categories}
    all_protocols_found = {cat: set() for cat in protocol_categories}

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        line_countries = set()
        line_configs = set()

        # Find countries on this line
        for country, patterns in country_categories.items():
            for pattern in patterns:
                if pattern.search(line):
                    line_countries.add(country)
                    break

        # Find configs on this line
        for protocol, patterns in protocol_patterns.items():
            for pattern in patterns:
                matches = pattern.findall(line)
                if matches:
                    line_configs.update(matches)
                    all_protocols_found[protocol].update(matches)

        # Associate if both found on the *same line*
        if line_countries and line_configs:
            for country in line_countries:
                associated_configs[country].update(line_configs)

    return associated_configs, all_protocols_found


def save_to_file(directory, category_name, items_set):
    """Helper function to save a set to a file."""
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
    md_content += "**توضیح:** فایل‌های کشورها فقط شامل کانفیگ‌هایی هستند که در **همان خط** با نام/پرچم کشور پیدا شده‌اند.\n\n"

    md_content += "## 📁 فایل‌های پروتکل‌ها\n\n"
    md_content += "| پروتکل | تعداد کل | لینک |\n"
    md_content += "|---|---|---|\n"
    for category, count in sorted(protocol_counts.items()):
        md_content += f"| {category} | {count} | [`{category}.txt`](./{OUTPUT_DIR}/{category}.txt) |\n"
    md_content += "\n"

    md_content += "## 🌍 فایل‌های کشورها (حاوی کانفیگ)\n\n"
    md_content += "| کشور | تعداد کانفیگ مرتبط | لینک |\n"
    md_content += "|---|---|---|\n"
    for category, count in sorted(country_counts.items()):
        md_content += f"| {category} | {count} | [`{category}.txt`](./{OUTPUT_DIR}/{category}.txt) |\n"
    md_content += "\n"

    try:
        with open(README_FILE, 'w', encoding='utf-8') as f:
            f.write(md_content)
        logging.info(f"Successfully generated {README_FILE}")
    except Exception as e:
        logging.error(f"Failed to write {README_FILE}: {e}")

async def main():
    """Main function."""
    if not os.path.exists(URLS_FILE) or not os.path.exists(KEYWORDS_FILE):
        logging.critical("Input files not found.")
        return

    with open(URLS_FILE, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]
    with open(KEYWORDS_FILE, 'r', encoding='utf-8') as f:
        categories = json.load(f)

    compiled_categories = compile_patterns(categories)
    country_category_names = [cat for cat in categories if cat not in PROTOCOL_CATEGORIES]

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

    logging.info("Processing pages for line-by-line association...")
    for url, text in fetched_pages:
        if text:
            url_country_configs, url_protocols = process_text_line_by_line(
                text, compiled_categories, PROTOCOL_CATEGORIES
            )
            for country, configs in url_country_configs.items():
                final_configs_by_country[country].update(configs)
            for protocol, configs in url_protocols.items():
                final_all_protocols[protocol].update(configs)

    # --- Save Output Files ---
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    logging.info(f"Saving files to directory: {OUTPUT_DIR}")

    protocol_counts = {}
    country_counts = {}

    # Save protocol files
    for category, items in final_all_protocols.items():
        saved, count = save_to_file(OUTPUT_DIR, category, items)
        if saved: protocol_counts[category] = count

    # Save country files (with associated configs)
    for category, items in final_configs_by_country.items():
        saved, count = save_to_file(OUTPUT_DIR, category, items)
        if saved: country_counts[category] = count

    # --- Generate README.md ---
    generate_simple_readme(protocol_counts, country_counts)

    logging.info("--- Script Finished ---")

if __name__ == "__main__":
    asyncio.run(main())
