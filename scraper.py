import asyncio
import aiohttp
import json
import re
import logging
from bs4 import BeautifulSoup
import os

# --- Configuration ---
URLS_FILE = 'urls.txt'
KEYWORDS_FILE = 'keywords.json'
OUTPUT_FILE = 'results.json'
REQUEST_TIMEOUT = 15  # seconds
CONCURRENT_REQUESTS = 10  # Max concurrent requests

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

async def fetch_url(session, url):
    """
    Asynchronously fetches the content of a single URL.

    Args:
        session: An aiohttp.ClientSession object.
        url: The URL string to fetch.

    Returns:
        A tuple containing the URL and its text content (str),
        or the URL and None if fetching fails.
    """
    try:
        # Fetch the URL with a timeout
        async with session.get(url, timeout=REQUEST_TIMEOUT) as response:
            # Raise an exception for bad status codes (4xx or 5xx)
            response.raise_for_status()
            # Read the response text
            html = await response.text()
            # Use BeautifulSoup to extract text, ignoring HTML tags
            soup = BeautifulSoup(html, 'html.parser')
            text = soup.get_text(separator=' ', strip=True)
            logging.info(f"Successfully fetched: {url}")
            return url, text
    except aiohttp.ClientError as e:
        logging.warning(f"Failed to fetch {url}: ClientError - {e}")
        return url, None
    except asyncio.TimeoutError:
        logging.warning(f"Failed to fetch {url}: TimeoutError")
        return url, None
    except Exception as e:
        logging.error(f"An unexpected error occurred for {url}: {e}")
        return url, None

def find_matches(text, categories):
    """
    Finds matches for keywords and regex patterns within the text.

    Args:
        text: The text content (str) to search within.
        categories: A dictionary mapping category names to lists of 
                    keywords or regex patterns.

    Returns:
        A dictionary where keys are category names and values are 
        lists of found matches (str).
    """
    matches = {category: [] for category in categories}
    
    for category, patterns in categories.items():
        for pattern in patterns:
            try:
                # Treat each pattern as a potential regex. 
                # For simple keywords, findall works.
                # For protocols, ensure we capture the whole block.
                # We use re.findall to find all non-overlapping matches.
                # We add word boundaries `\b` for protocol patterns to avoid merging,
                # but need to be careful not to break complex regex.
                # A safer approach is to ensure the regex itself is well-defined.
                # For protocols like vmess, we look for the specific prefix and
                # a sequence of characters until a likely end (space, newline, quote).
                # The provided example regexes seem designed for this.
                
                # Use findall for both keywords and regex.
                found = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
                
                if found:
                    # Add unique matches to the list for the category
                    for item in found:
                       if item not in matches[category]:
                           matches[category].append(item)
                           
            except re.error as e:
                logging.error(f"Invalid regex pattern '{pattern}' "
                              f"for category '{category}': {e}")
                
    return matches

async def main():
    """
    Main function to coordinate the scraping process.
    """
    # --- Read Input Files ---
    if not os.path.exists(URLS_FILE):
        logging.critical(f"Input file not found: {URLS_FILE}")
        return
    if not os.path.exists(KEYWORDS_FILE):
        logging.critical(f"Input file not found: {KEYWORDS_FILE}")
        return

    with open(URLS_FILE, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]

    with open(KEYWORDS_FILE, 'r') as f:
        categories = json.load(f)

    logging.info(f"Loaded {len(urls)} URLs and "
                 f"{len(categories)} categories.")

    # --- Fetch URLs Concurrently ---
    results = {}
    tasks = []
    # Use a semaphore to limit concurrent requests
    sem = asyncio.Semaphore(CONCURRENT_REQUESTS)

    async def fetch_with_sem(session, url):
        """Wrapper to use semaphore with fetch_url."""
        async with sem:
            return await fetch_url(session, url)

    # Create a single aiohttp session for connection pooling
    async with aiohttp.ClientSession() as session:
        for url in urls:
            tasks.append(fetch_with_sem(session, url))
        
        # Wait for all fetch tasks to complete
        fetched_pages = await asyncio.gather(*tasks)

    # --- Process Results and Find Matches ---
    for url, text in fetched_pages:
        if text:
            logging.info(f"Processing matches for: {url}")
            results[url] = find_matches(text, categories)
        else:
            # Skip failed URLs but keep a record or handle as needed
            results[url] = {"error": "Failed to fetch or process"}
            logging.info(f"Skipping failed URL: {url}")

    # --- Output Results ---
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    logging.info(f"Scraping complete. Results saved to {OUTPUT_FILE}")

# --- Run the main function ---
if __name__ == "__main__":
    asyncio.run(main())
