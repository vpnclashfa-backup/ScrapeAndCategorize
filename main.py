# مسیر: main.py

import asyncio
import aiohttp
from config import settings
from utils.file_handler import read_urls_from_file, load_keywords
from utils.logger_setup import setup_logger
from core.fetcher import fetch_and_normalize_content
from core.parser import analyze_content # ایمپورت تابع تحلیلگر

async def main():
    """
    نقطه شروع اصلی برنامه
    """
    logger = setup_logger()
    logger.info("="*50)
    logger.info("اسکریپت جمع‌آوری و دسته‌بندی کانفیگ‌ها شروع به کار کرد")
    logger.info("="*50)

    # خواندن فایل‌های ورودی (لینک‌ها و کلمات کلیدی)
    plain_urls = read_urls_from_file(settings.PLAIN_CONTENT_URLS_FILE)
    base64_urls = read_urls_from_file(settings.BASE64_CONTENT_URLS_FILE)
    keywords = load_keywords(settings.KEYWORDS_FILE)

    if not plain_urls and not base64_urls:
        logger.error("هیچ URL ای در فایل‌های ورودی یافت نشد. برنامه متوقف می‌شود.")
        return
    if not keywords:
        logger.error("فایل keywords.json یافت نشد یا خالی است. برنامه متوقف می‌شود.")
        return

    logger.info(f"خوانده شد: {len(plain_urls)} لینک عادی، {len(base64_urls)} لینک Base64، و {len(keywords)} کلیدواژه.")

    tasks = []
    async with aiohttp.ClientSession() as session:
        for url in plain_urls:
            tasks.append(fetch_and_normalize_content(session, url, is_base64_content=False, logger=logger))
        
        for url in base64_urls:
            tasks.append(fetch_and_normalize_content(session, url, is_base64_content=True, logger=logger))

        results = await asyncio.gather(*tasks)

    logger.info("--- شروع تحلیل و آماردهی محتوای دریافت شده ---")
    
    all_normalized_content = ""
    successful_fetches = 0
    for url, content in results:
        if content:
            successful_fetches += 1
            # تحلیل محتوای هر لینک به صورت جداگانه
            stats = analyze_content(content, keywords)
            if stats['total'] > 0:
                # فرمت‌دهی زیبا برای لاگ آمار
                protocol_stats_str = ", ".join([f"{p}: {c}" for p, c in stats['protocols'].items()])
                logger.info(
                    f"📊 آمار برای {url} -> "
                    f"کل: {stats['total']}, "
                    f"ایران: {stats['iran_count']}, "
                    f"[{protocol_stats_str}]"
                )
            else:
                logger.info(f"⚪️ برای {url} هیچ کانفیگ قابل تشخیصی یافت نشد.")
            
            all_normalized_content += content + "\n"
    
    logger.info(f"تحلیل برای {successful_fetches} لینک با موفقیت انجام شد.")
    
    logger.info("="*50)
    logger.info("اجرای اسکریپت به پایان رسید")
    logger.info("="*50)


if __name__ == "__main__":
    asyncio.run(main())
