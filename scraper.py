import asyncio
import aiohttp
import json
import re
import logging
from bs4 import BeautifulSoup
import os
import shutil  # <--- کتابخانه جدید برای حذف پوشه

# --- Configuration ---
URLS_FILE = 'urls.txt'
KEYWORDS_FILE = 'keywords.json'
OUTPUT_DIR = 'output_configs'  # نام پوشه خروجی
REQUEST_TIMEOUT = 15  # seconds
CONCURRENT_REQUESTS = 10  # Max concurrent requests

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- لیست پروتکل‌هایی که می‌خواهیم برایشان فایل بسازیم ---
PROTOCOL_CATEGORIES = [
    "Vmess", "Vless", "Trojan", "ShadowSocks", "ShadowSocksR",
    "Tuic", "Hysteria2", "WireGuard"
]

async def fetch_url(session, url):
    """
    Asynchronously fetches the content of a single URL.
    Returns: Tuple (url, text_content or None).
    """
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
    """
    Finds matches for keywords and regex patterns within the text.
    Returns: Dict {category: [matches]}.
    """
    matches = {category: [] for category in categories}
    for category, patterns in categories.items():
        for pattern in patterns:
            try:
                found = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
                if found:
                    for item in found:
                        if item not in matches[category]:
                            matches[category].append(item)
            except re.error as e:
                logging.error(f"Invalid regex pattern '{pattern}' "
                              f"for category '{category}': {e}")
    return matches

async def main():
    """
    Main function: Reads inputs, fetches URLs, processes, and saves results.
    """
    # --- Read Input Files ---
    if not os.path.exists(URLS_FILE) or not os.path.exists(KEYWORDS_FILE):
        logging.critical("Input files (urls.txt or keywords.json) not found.")
        return

    with open(URLS_FILE, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]
    with open(KEYWORDS_FILE, 'r', encoding='utf-8') as f:
        categories = json.load(f)

    logging.info(f"Loaded {len(urls)} URLs and "
                 f"{len(categories)} categories.")

    # --- Fetch URLs Concurrently ---
    tasks = []
    sem = asyncio.Semaphore(CONCURRENT_REQUESTS)
    all_found_items = {category: set() for category in categories}

    async def fetch_with_sem(session, url):
        async with sem:
            return await fetch_url(session, url)

    async with aiohttp.ClientSession() as session:
        fetched_pages = await asyncio.gather(*[fetch_with_sem(session, url) for url in urls])

    # --- Process Results and Aggregate Matches ---
    logging.info("Processing all fetched pages...")
    for url, text in fetched_pages:
        if text:
            url_matches = find_matches(text, categories)
            for category, items in url_matches.items():
                all_found_items[category].update(items)

    # --- Output Results to Separate Files ---
    # <<<--- تغییر مهم: حذف پوشه قدیمی و ایجاد پوشه جدید --->>>
    if os.path.exists(OUTPUT_DIR):
        logging.info(f"Removing old directory: {OUTPUT_DIR}")
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    logging.info(f"Saving results to directory: {OUTPUT_DIR}")
    # <<<--- پایان تغییر مهم --->>>

    total_saved_configs = 0
    for category in PROTOCOL_CATEGORIES:
        items = all_found_items.get(category)
        if items:
            file_path = os.path.join(OUTPUT_DIR, f"{category}.txt")
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    for item in sorted(list(items)):
                        f.write(f"{item}\n")
                logging.info(f"Saved {len(items)} items to {file_path}")
                total_saved_configs += len(items)
            except Exception as e:
                logging.error(f"Failed to write file {file_path}: {e}")

    logging.info(f"Scraping complete. Saved {total_saved_configs} configs.")

if __name__ == "__main__":
    asyncio.run(main())
