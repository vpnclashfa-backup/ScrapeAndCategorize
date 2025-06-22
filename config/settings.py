# مسیر: config/settings.py

# --- Input Files Configuration ---
# مسیر فایل‌های ورودی که لینک‌ها در آن‌ها قرار دارند.
# این مسیرها نسبت به پوشه اصلی پروژه (ریشه) هستند.
PLAIN_CONTENT_URLS_FILE = 'inputs/plain_content_urls.txt'
BASE64_CONTENT_URLS_FILE = 'inputs/base64_content_urls.txt'
KEYWORDS_FILE = 'config/keywords.json'

# --- Output Directories & Files Configuration ---
# نام پوشه‌ها و فایل‌هایی که به عنوان خروجی ساخته می‌شوند.
OUTPUT_DIR = 'output_configs'
BASE64_IRAN_DIR = 'output_base64_iran' # پوشه برای کانفیگ‌های Base64 شده ایران
README_FILE = 'README.md'
LOG_FILE = 'run_log.log' # نام فایل لاگ که در مراحل بعد استفاده می‌شود

# --- Network Request Configuration ---
# تنظیمات مربوط به درخواست‌های اینترنتی
REQUEST_TIMEOUT = 15  # حداکثر زمان انتظار برای هر درخواست به ثانیه
CONCURRENT_REQUESTS = 10  # تعداد درخواست‌های همزمانی که ارسال می‌شود

# --- Config Filtering Configuration ---
# تنظیمات برای فیلتر کردن کانفیگ‌های نامعتبر
MAX_CONFIG_LENGTH = 1500  # حداکثر طول مجاز برای یک رشته کانفیگ
MIN_PERCENT25_COUNT = 15  # حداقل تعداد کاراکتر %25 برای فیلتر کردن

# --- Protocol Categories ---
# لیست پروتکل‌هایی که اسکریپت به دنبال آن‌ها می‌گردد.
PROTOCOL_CATEGORIES = [
    "Vmess", "Vless", "Trojan", "ShadowSocks", "ShadowSocksR",
    "Tuic", "Hysteria2", "WireGuard"
]

# --- GitHub Repo Configuration for README ---
# اطلاعات مخزن گیت‌هاب شما برای ساخت لینک‌های دانلود در فایل README
GITHUB_REPO_PATH = "PacketEscape/ScrapeAndCategorize"
GITHUB_BRANCH = "main"

