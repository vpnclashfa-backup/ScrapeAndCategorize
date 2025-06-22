# مسیر: main.py

import asyncio
import aiohttp
from config import settings
from utils.file_handler import read_urls_from_file
from utils.logger_setup import setup_logger
from core.fetcher import fetch_and_normalize_content

async def main():
    """
    نقطه شروع اصلی برنامه
    """
    # گام اول: تنظیم و فعال‌سازی لاگر
    logger = setup_logger()
    logger.info("="*50)
    logger.info("اسکریپت جمع‌آوری و دسته‌بندی کانفیگ‌ها شروع به کار کرد")
    logger.info("="*50)

    # خواندن URL ها از هر دو فایل
    plain_urls = read_urls_from_file(settings.PLAIN_CONTENT_URLS_FILE)
    base64_urls = read_urls_from_file(settings.BASE64_CONTENT_URLS_FILE)

    if not plain_urls and not base64_urls:
        logger.error("هیچ URL ای در فایل‌های ورودی یافت نشد. برنامه متوقف می‌شود.")
        return

    logger.info(f"خوانده شد: {len(plain_urls)} لینک با محتوay عادی، {len(base64_urls)} لینک با محتوای Base64.")

    tasks = []
    async with aiohttp.ClientSession() as session:
        for url in plain_urls:
            tasks.append(fetch_and_normalize_content(session, url, is_base64_content=False, logger=logger))
        
        for url in base64_urls:
            tasks.append(fetch_and_normalize_content(session, url, is_base64_content=True, logger=logger))

        results = await asyncio.gather(*tasks)

    logger.info("--- پردازش محتوای دریافت شده ---")
    all_normalized_content = ""
    successful_fetches = 0
    for url, content in results:
        if content:
            successful_fetches += 1
            all_normalized_content += content + "\n"
    
    logger.info(f"محتوا از {successful_fetches} لینک با موفقیت دریافت و نرمال‌سازی شد.")
    
    # در مراحل بعدی، `all_normalized_content` برای پردازش نهایی استفاده خواهد شد.
    # برای مثال، می‌توانیم تعداد خطوط محتوای جمع‌آوری شده را لاگ کنیم:
    total_lines = len(all_normalized_content.strip().split('\n'))
    logger.info(f"در مجموع {total_lines} خط محتوا برای پردازش آماده است.")
    
    logger.info("="*50)
    logger.info("اجرای اسکریپت به پایان رسید")
    logger.info("="*50)


if __name__ == "__main__":
    asyncio.run(main())
