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
            text = soup.get_text(separator=' ', strip=True)
            logging.info(f"Successfully fetched: {url}")
            return url, text
    except Exception as e:
        logging.warning(f"Failed to fetch or process {url}: {e}")
        return url, None

def find_matches(text, categories):
    """Finds matches in text and returns {category: set_of_items}."""
    matches = {category: set() for category in categories}
    for category, patterns in categories.items():
        for pattern in patterns:
            try:
                found = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
                if found:
                    matches[category].update(found)
            except re.error as e:
                logging.error(f"Regex error for '{pattern}': {e}")
    return {k: v for k, v in matches.items() if v}

def save_to_file(directory, category_name, items_set):
    """Helper function to save a set to a file."""
    if not items_set:
        return False
    file_path = os.path.join(directory, f"{category_name}.txt")
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            for item in sorted(list(items_set)):
                f.write(f"{item}\n")
        logging.info(f"Saved {len(items_set)} items to {file_path}")
        return True
    except Exception as e:
        logging.error(f"Failed to write file {file_path}: {e}")
        return False

def generate_readme(results_per_url, categories_with_files):
    """Generates the README.md content."""
    tz = pytz.timezone('Asia/Tehran')
    now = datetime.now(tz)
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S %Z")

    md_content = f"# 📊 نتایج استخراج (آخرین به‌روزرسانی: {timestamp})\n\n"
    md_content += "این فایل به صورت خودکار توسط GitHub Actions ایجاد شده است.\n\n"
    md_content += "**نکته مهم:** فایل‌های مربوط به **کشورها**، حاوی **کانفیگ‌های** یافت شده در صفحاتی هستند که به آن کشور اشاره داشته‌اند.\n\n"

    md_content += "## 🔗 لینک‌های سریع به تمام فایل‌های خروجی\n\n"
    for category in sorted(categories_with_files):
        md_content += f"* [{category}](./{OUTPUT_DIR}/{category}.txt)\n"
    md_content += "\n---\n"

    md_content += "## 📄 جزئیات بر اساس URL (موارد شناسایی شده)\n\n"

    if not results_per_url:
        md_content += "هیچ URLی پردازش نشد یا هیچ نتیجه‌ای یافت نشد.\n"
    else:
        for url, categories_found in sorted(results_per_url.items()):
            md_content += f"### `{url}`\n\n"

            if "error" in categories_found:
                md_content += "* ⚠️ *خطا در دریافت یا پردازش این URL.*\n"
            elif not categories_found:
                md_content += "* *هیچ کلمه کلیدی یا کانفیگی یافت نشد.*\n"
            else:
                md_content += "| دسته | تعداد (موارد شناسایی شده) | لینک فایل |\n"
                md_content += "|---|---|---|\n"
                for category, items in sorted(categories_found.items()):
                    count = len(items)
                    link = f"[`{category}.txt`](./{OUTPUT_DIR}/{category}.txt)" if category in categories_with_files else "-"
                    md_content += f"| {category} | {count} | {link} |\n"
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
        logging.critical("Input files (urls.txt or keywords.json) not found.")
        return

    with open(URLS_FILE, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]
    with open(KEYWORDS_FILE, 'r', encoding='utf-8') as f:
        categories = json.load(f)

    all_category_names = list(categories.keys())
    country_category_names = [cat for cat in all_category_names if cat not in PROTOCOL_CATEGORIES]

    logging.info(f"Loaded {len(urls)} URLs and "
                 f"{len(categories)} categories.")

    # --- Fetch URLs ---
    tasks = []
    sem = asyncio.Semaphore(CONCURRENT_REQUESTS)
    results_per_url = {}

    async def fetch_with_sem(session, url):
        async with sem:
            return await fetch_url(session, url)

    async with aiohttp.ClientSession() as session:
        fetched_pages = await asyncio.gather(*[fetch_with_sem(session, url) for url in urls])

    # --- Process Results (Store original findings) ---
    logging.info("Processing all fetched pages...")
    for url, text in fetched_pages:
        if text:
            results_per_url[url] = find_matches(text, categories)
        else:
            results_per_url[url] = {"error": True}

    # --- Aggregate for File Output (New Logic) ---
    configs_by_country = {cat: set() for cat in country_category_names}
    all_protocol_configs = {cat: set() for cat in PROTOCOL_CATEGORIES}

    for url, categories_found in results_per_url.items():
        if "error" in categories_found or not categories_found:
            continue

        page_configs = set()
        page_countries = set()

        for cat, items in categories_found.items():
            if cat in PROTOCOL_CATEGORIES:
                page_configs.update(items)
                all_protocol_configs[cat].update(items)
            else:
                page_countries.add(cat) # Add country category name

        # Associate configs with countries found on the same page
        if page_configs and page_countries:
            for country in page_countries:
                configs_by_country[country].update(page_configs)

    # --- Save Output Files ---
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    logging.info(f"Saving files to directory: {OUTPUT_DIR}")

    categories_with_files = []

    # Save protocol files (all configs of a type)
    for category, items in all_protocol_configs.items():
        if save_to_file(OUTPUT_DIR, category, items):
            categories_with_files.append(category)

    # Save country files (configs associated with a country)
    for category, items in configs_by_country.items():
        if save_to_file(OUTPUT_DIR, category, items):
            categories_with_files.append(category)

    # --- Generate README.md ---
    generate_readme(results_per_url, categories_with_files)

    logging.info("--- Script Finished ---")

if __name__ == "__main__":
    asyncio.run(main())
