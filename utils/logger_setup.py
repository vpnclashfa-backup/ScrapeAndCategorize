# مسیر: utils/logger_setup.py

import logging
import colorlog
from config import settings

# نگاشت نام سطح لاگ به فارسی
PERSIAN_LEVEL_NAMES = {
    logging.DEBUG: "دیباگ",
    logging.INFO: "اطلاعات",
    logging.WARNING: "هشدار",
    logging.ERROR: "خطا",
    logging.CRITICAL: "بحرانی"
}

def setup_logger():
    """
    لاگر اصلی برنامه را با دو handler تنظیم می‌کند:
    1. StreamHandler: برای نمایش لاگ‌های رنگی در کنسول.
    2. FileHandler: برای ذخیره تمام لاگ‌ها در یک فایل.
    """
    # تغییر نام پیش‌فرض سطوح لاگ به فارسی
    for level, name in PERSIAN_LEVEL_NAMES.items():
        logging.addLevelName(level, name)

    # ایجاد یک لاگر با نام مشخص
    logger = logging.getLogger("ScraperApp")
    logger.setLevel(logging.INFO)  # حداقل سطح لاگ برای نمایش

    # جلوگیری از افزودن چندباره handler ها در صورت فراخوانی مجدد تابع
    if logger.hasHandlers():
        logger.handlers.clear()

    # 1. تنظیمات Handler برای کنسول (رنگی)
    console_handler = colorlog.StreamHandler()
    console_formatter = colorlog.ColoredFormatter(
        '%(log_color)s[%(levelname)-8s]%(reset)s - %(message)s',
        log_colors={
            'دیباگ': 'cyan',
            'اطلاعات': 'green',
            'هشدار': 'yellow',
            'خطا': 'red',
            'بحرانی': 'red,bg_white',
        },
        reset=True,
        style='%'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # 2. تنظیمات Handler برای فایل (بدون رنگ)
    file_handler = logging.FileHandler(settings.LOG_FILE, mode='w', encoding='utf-8')
    file_formatter = logging.Formatter(
        '[%(levelname)-8s] - %(asctime)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    return logger
