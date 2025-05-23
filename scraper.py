import asyncio
import aiohttp
import json
import re
import logging
from bs4 import BeautifulSoup
import os
import shutil
from datetime import datetime
import pytz  # <--- کتابخانه جدید برای زمان

# --- Configuration ---
URLS_FILE = 'urls.txt'
KEYWORDS_FILE = 'keywords.json'
OUTPUT_DIR = 'output_configs'
README_FILE = 'README.md'  # <--- نام فایل ریدمی
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
    """Finds matches in text."""
    matches = {category: set() for category in categories} # Use set for uniqueness
    for category, patterns in categories.items():
        for pattern in patterns:
            try:
                found = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
                if found:
                    matches[category].update(found) # Add to set
            except re.error as e:
                logging.error(f"Regex error for '{pattern}': {e}")
    # Return only categories with matches
    return {k: v for k, v in matches.items() if v}


def generate_readme(results_per_url, protocol_categories):
    """Generates the README.md content."""
    tz = pytz.timezone('Asia/Tehran')
    now = datetime.now(tz)
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S %Z")

    md_content = f"# 📊 نتایج استخراج کانفیگ (آخرین به‌روزرسانی: {timestamp})\n\n"
    md_content += "این فایل به صورت خودکار توسط GitHub Actions ایجاد شده است.\n\n"
    md_content += "## 🔗 لینک‌های سریع به فایل‌های کانفیگ\n\n"

    # Add links only for protocols that *might* have files
    for category in protocol_categories:
        md_content += f"* [{category}](./{OUTPUT_DIR}/{category}.txt)\n"
    md_content += "\n---\n"

    md_content += "## 📄 جزئیات بر اساس URL\n\n"

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
                md_content += "| دسته | تعداد | لینک فایل |\n"
                md_content += "|---|---|---|\n"
                for category, items in sorted(categories_found.items()):
                    count = len(items)
                    link = f"[`{category}.txt`](./{OUTPUT_DIR}/{category}.txt)" if category in protocol_categories else "-"
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

    logging.info(f"Loaded {len(urls)} URLs and "
                 f"{len(categories)} categories.")

    # --- Fetch URLs ---
    tasks = []
    sem = asyncio.Semaphore(CONCURRENT_REQUESTS)
    results_per_url = {}  # <--- برای نگهداری نتایج هر URL
    all_found_items = {category: set() for category in categories} # <--- برای agreggration

    async def fetch_with_sem(session, url):
        async with sem:
            return await fetch_url(session, url)

    async with aiohttp.ClientSession() as session:
        fetched_pages = await asyncio.gather(*[fetch_with_sem(session, url) for url in urls])

    # --- Process Results ---
    logging.info("Processing all fetched pages...")
    for url, text in fetched_pages:
        if text:
            url_matches = find_matches(text, categories)
            results_per_url[url] = url_matches # ذخیره نتایج این URL
            for category, items in url_matches.items():
                all_found_items[category].update(items) # اضافه به نتایج کلی
        else:
            results_per_url[url] = {"error": True} # علامت‌گذاری خطا

    # --- Save Protocol Files ---
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    logging.info(f"Saving protocol files to directory: {OUTPUT_DIR}")

    total_saved_configs = 0
    for category in PROTOCOL_CATEGORIES:
        items = all_found_items.get(category)
        if items:
            file_path = os.path.join(OUTPUT_DIR, f"{category}.txt")
            with open(file_path, 'w', encoding='utf-8') as f:
                for item in sorted(list(items)):
                    f.write(f"{item}\n")
            logging.info(f"Saved {len(items)} items to {file_path}")
            total_saved_configs += len(items)

    logging.info(f"Saved {total_saved_configs} configs.")

    # --- Generate README.md ---
    generate_readme(results_per_url, PROTOCOL_CATEGORIES) # <--- فراخوانی تابع جدید

    logging.info("--- Script Finished ---")

if __name__ == "__main__":
    asyncio.run(main())
