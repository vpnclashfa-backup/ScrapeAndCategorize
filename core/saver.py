# مسیر: core/saver.py

import os
import shutil
import base64
import pytz
from datetime import datetime
from logging import Logger
from config import settings
from utils.text_helpers import is_persian_like

# توابع prepare_output_dirs, save_configs_to_file, encode_and_save_base64
# بدون تغییر باقی می‌مانند.
def prepare_output_dirs(dirs_to_clean: list, logger: Logger):
    for directory in dirs_to_clean:
        try:
            if os.path.exists(directory):
                shutil.rmtree(directory)
                logger.info(f"پوشه قدیمی {directory} با موفقیت حذف شد.")
            os.makedirs(directory)
            logger.info(f"پوشه {directory} با موفقیت ایجاد شد.")
        except OSError as e:
            logger.error(f"خطا در مدیریت پوشه {directory}: {e}")

def save_configs_to_file(directory: str, filename: str, configs: set, logger: Logger) -> int:
    if not configs: return 0
    count = len(configs)
    file_path = os.path.join(directory, f"{filename}.txt")
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            for item in sorted(list(configs)):
                f.write(f"{item}\n")
        logger.info(f"تعداد {count} کانفیگ در فایل {file_path} ذخیره شد.")
        return count
    except IOError as e:
        logger.error(f"خطا در نوشتن فایل {file_path}: {e}")
        return 0

def encode_and_save_base64(directory: str, filename: str, configs: set, logger: Logger):
    if not configs: return
    full_content = "\n".join(sorted(list(configs)))
    encoded_content = base64.b64encode(full_content.encode('utf-8')).decode('utf-8')
    file_path = os.path.join(directory, f"{filename}.txt")
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(encoded_content)
        logger.info(f"خروجی Base64 برای {len(configs)} کانفیگ در فایل {file_path} ذخیره شد.")
    except IOError as e:
        logger.error(f"خطا در نوشتن فایل Base64 در {file_path}: {e}")


def generate_readme(protocol_counts: dict, country_counts: dict, all_keywords: dict, logger: Logger):
    """فایل README.md و فایل‌های متنی حاوی لینک‌ها را تولید می‌کند."""
    tz = pytz.timezone('Asia/Tehran')
    now = datetime.now(tz)
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S %Z")
    
    base_url = f"https://raw.githubusercontent.com/{settings.GITHUB_REPO_PATH}/refs/heads/{settings.GITHUB_BRANCH}"
    normal_configs_url = f"{base_url}/{settings.OUTPUT_DIR}"
    base64_configs_url = f"{base_url}/{settings.BASE64_OUTPUT_DIR}"
    
    # *** تغییر ۱: ایجاد دو لیست خالی برای جمع‌آوری لینک‌ها ***
    all_normal_links = []
    all_base64_links = []

    md_content = f"# Configs (آخرین به‌روزرسانی: {timestamp})\n\n"
    md_content += "## دسته‌بندی بر اساس پروتکل\n\n"
    md_content += "| پروتکل | تعداد | لینک دانلود |\n|---|---|---|\n"
    for category, count in sorted(protocol_counts.items()):
        file_link = f"{normal_configs_url}/{category}.txt"
        all_normal_links.append(file_link) # *** افزودن لینک به لیست ***
        md_content += f"| {category} | {count} | [`{category}.txt`]({file_link}) |\n"
    
    md_content += "\n## دسته‌بندی بر اساس کشور\n\n"
    md_content += "| کشور | تعداد | لینک نرمال | لینک بیس۶۴ |\n|---|---|---|---|\n"
    for country, count in sorted(country_counts.items()):
        keywords_list = all_keywords.get(country, [])
        iso_code = next((k.lower() for k in keywords_list if len(k) == 2 and k.isalpha()), None)
        persian_name = next((k for k in keywords_list if is_persian_like(k)), "")
        
        flag_md = f'<img src="https://flagcdn.com/w20/{iso_code}.png" width="20">' if iso_code else ""
        country_display = f"{flag_md} {country} ({persian_name})" if persian_name else f"{flag_md} {country}"
        
        normal_link_url = f"{normal_configs_url}/{country}.txt"
        base64_link_url = f"{base64_configs_url}/{country}.txt"
        
        all_normal_links.append(normal_link_url) # *** افزودن لینک به لیست ***
        all_base64_links.append(base64_link_url) # *** افزودن لینک به لیست ***
        
        normal_link_md = f"[`{country}.txt`]({normal_link_url})"
        base64_link_md = f"[`{country}.txt`]({base64_link_url})"
        
        md_content += f"| {country_display.strip()} | {count} | {normal_link_md} | {base64_link_md} |\n"

    # نوشتن فایل README.md
    try:
        with open(settings.README_FILE, 'w', encoding='utf-8') as f:
            f.write(md_content)
        logger.info(f"فایل {settings.README_FILE} با موفقیت تولید شد.")
    except IOError as e:
        logger.error(f"خطا در نوشتن فایل {settings.README_FILE}: {e}")
        
    # *** تغییر ۲: ذخیره کردن لینک‌های جمع‌آوری شده در فایل‌های متنی ***
    try:
        with open(settings.NORMAL_LINKS_FILE, 'w', encoding='utf-8') as f:
            # استفاده از set برای حذف موارد تکراری و سپس مرتب‌سازی
            f.write("\n".join(sorted(list(set(all_normal_links)))))
        logger.info(f"فایل لینک‌های نرمال در {settings.NORMAL_LINKS_FILE} ذخیره شد.")

        with open(settings.BASE64_LINKS_FILE, 'w', encoding='utf-8') as f:
            f.write("\n".join(sorted(list(set(all_base64_links)))))
        logger.info(f"فایل لینک‌های Base64 در {settings.BASE64_LINKS_FILE} ذخیره شد.")
    except IOError as e:
        logger.error(f"خطا در نوشتن فایل‌های لینک: {e}")
