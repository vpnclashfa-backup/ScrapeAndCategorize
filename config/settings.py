# مسیر: config/settings.py

# --- Input Files Configuration ---
PLAIN_CONTENT_URLS_FILE = 'inputs/plain_content_urls.txt'
BASE64_CONTENT_URLS_FILE = 'inputs/base64_content_urls.txt'
KEYWORDS_FILE = 'config/keywords.json'

# --- Output Directories & Files Configuration ---
OUTPUT_DIR = 'output_configs'
# نام پوشه خروجی برای تمام فایل‌های Base64 کشورها
BASE64_OUTPUT_DIR = 'output_base64_countries'
README_FILE = 'README.md'
LOG_FILE = 'run_log.log'

# --- Network Request Configuration ---
REQUEST_TIMEOUT = 15
CONCURRENT_REQUESTS = 10

# --- Config Filtering Configuration ---
MAX_CONFIG_LENGTH = 1500
MIN_PERCENT25_COUNT = 15

# --- Protocol Categories ---
PROTOCOL_CATEGORIES = [
    "Vmess", "Vless", "Trojan", "ShadowSocks", "ShadowSocksR",
    "Tuic", "Hysteria2", "WireGuard"
]

# --- GitHub Repo Configuration for README ---
# آدرس مخزن گیت‌هاب به vpnclashfa-backup تغییر یافت
GITHUB_REPO_PATH = "vpnclashfa-backup/ScrapeAndCategorize"
GITHUB_BRANCH = "main"


# --- Output Link Files ---
# فایل‌هایی برای ذخیره لینک‌های خام تولید شده
NORMAL_LINKS_FILE = 'output_normal_links.txt'
BASE64_LINKS_FILE = 'output_base64_links.txt'


# --- متغیر COUNTRIES_TO_ENCODE حذف شد ---
# چون برای تمام کشورها خروجی Base64 ساخته می‌شود، دیگر به این متغیر نیازی نیست.
