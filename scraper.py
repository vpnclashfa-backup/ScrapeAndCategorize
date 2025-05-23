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

def generate_readme(results_per_url, categories_with_files):
    """Generates the README.md content."""
    tz = pytz.timezone('Asia/Tehran')
    now = datetime.now(tz)
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S %Z")

    md_content = f"# 📊 نتایج استخراج (آخرین به‌روزرسانی: {timestamp})\n\n"
    md_content += "این فایل به صورت خودکار توسط GitHub Actions ایجاد شده است.\n\n"
    md_content += "## 🔗 لینک‌های سریع به تمام فایل‌ها\n\n"

    # <<<--- تغییر: لینک به تمام فایل‌های ایجاد شده (کشور و پروتکل) --->>>
    for category in sorted(categories_with_files):
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
                    # <<<--- تغییر: لینک به تمام دسته‌ها --->>>
                    link = f"[`{category}.txt`](./{OUTPUT_DIR}/{category}.txt)"
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
    results_per_url = {}
    all_found_items = {category: set() for category in categories}

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
            results_per_url[url] = url_matches
            for category, items in url_matches.items():
                all_found_items[category].update(items)
        else:
            results_per_url[url] = {"error": True}

    # --- Save Output Files ---
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    logging.info(f"Saving all found items to directory: {OUTPUT_DIR}")

    total_saved_items = 0
    categories_with_files = []
    # <<<--- تغییر: ایجاد فایل برای *تمام* دسته‌ها (کشور و پروتکل) --->>>
    for category, items in all_found_items.items():
        if items: # فقط اگر چیزی پیدا شده باشد فایل ایجاد کن
            categories_with_files.append(category)
            file_path = os.path.join(OUTPUT_DIR, f"{category}.txt")
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    for item in sorted(list(items)):
                        f.write(f"{item}\n")
                logging.info(f"Saved {len(items)} items to {file_path}")
                total_saved_items += len(items)
            except Exception as e:
                logging.error(f"Failed to write file {file_path}: {e}")

    logging.info(f"Saved a total of {total_saved_items} items across all files.")

    # --- Generate README.md ---
    generate_readme(results_per_url, categories_with_files) # <--- پاس دادن لیست فایل‌های ایجاد شده

    logging.info("--- Script Finished ---")

if __name__ == "__main__":
    asyncio.run(main())
