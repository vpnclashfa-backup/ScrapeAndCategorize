# مسیر: main.py

import asyncio
import aiohttp
from config import settings
from utils.file_handler import read_urls_from_file, load_keywords
from utils.logger_setup import setup_logger
from core.fetcher import fetch_and_normalize_content
from core.parser import analyze_content
from core.saver import prepare_output_dirs, save_configs_to_file, encode_and_save_base64, generate_readme

async def main():
    logger = setup_logger()
    logger.info("="*50)
    logger.info("اسکریپت جمع‌آوری و دسته‌بندی کانفیگ‌ها شروع به کار کرد")
    logger.info("="*50)

    # ۱. خواندن فایل‌های ورودی
    keywords = load_keywords(settings.KEYWORDS_FILE)
    if not keywords:
        logger.error("فایل keywords.json یافت نشد یا خالی است. برنامه متوقف می‌شود.")
        return
    
    plain_urls = read_urls_from_file(settings.PLAIN_CONTENT_URLS_FILE)
    base64_urls = read_urls_from_file(settings.BASE64_CONTENT_URLS_FILE)
    if not plain_urls and not base64_urls:
        logger.error("هیچ URL ای در فایل‌های ورودی یافت نشد. برنامه متوقف می‌شود.")
        return

    # ۲. واکشی محتوا از لینک‌ها
    tasks = []
    async with aiohttp.ClientSession() as session:
        for url in plain_urls: tasks.append(fetch_and_normalize_content(session, url, False, logger))
        for url in base64_urls: tasks.append(fetch_and_normalize_content(session, url, True, logger))
        results = await asyncio.gather(*tasks)

    # ۳. تحلیل و تجمیع نتایج
    logger.info("--- شروع تحلیل و تجمیع نتایج ---")
    country_names = [k for k in keywords if k not in settings.PROTOCOL_CATEGORIES]
    final_protocol_configs = {p: set() for p in settings.PROTOCOL_CATEGORIES}
    final_country_configs = {c: set() for c in country_names}

    for url, content in results:
        if not content: continue
        
        analysis_result = analyze_content(content, keywords)
        stats = analysis_result['stats']
        
        # لاگ کردن آمار هر لینک
        if stats['total'] > 0:
            protocol_stats_str = ", ".join([f"{p}: {c}" for p, c in stats['protocols'].items()])
            logger.info(f"📊 آمار برای {url} -> کل: {stats['total']}, ایران: {stats['iran_count']}, [{protocol_stats_str}]")
        
        # تجمیع نتایج
        for protocol, configs in analysis_result['protocol_configs'].items():
            final_protocol_configs[protocol].update(configs)
        for country, configs in analysis_result['country_configs'].items():
            final_country_configs[country].update(configs)

    # ۴. ذخیره‌سازی فایل‌ها
    logger.info("--- شروع ذخیره‌سازی فایل‌ها ---")
    prepare_output_dirs([settings.OUTPUT_DIR, settings.BASE64_IRAN_DIR], logger)
    
    protocol_counts = {}
    for protocol, configs in final_protocol_configs.items():
        count = save_configs_to_file(settings.OUTPUT_DIR, protocol, configs, logger)
        if count > 0: protocol_counts[protocol] = count

    country_counts = {}
    for country, configs in final_country_configs.items():
        count = save_configs_to_file(settings.OUTPUT_DIR, country, configs, logger)
        if count > 0: country_counts[country] = count

    # ذخیره نسخه Base64 برای کشورهای مشخص شده
    for country in settings.COUNTRIES_TO_ENCODE:
        if country in final_country_configs:
            encode_and_save_base64(settings.BASE64_IRAN_DIR, country, final_country_configs[country], logger)

    # ۵. تولید فایل README.md
    logger.info("--- تولید گزارش نهایی ---")
    generate_readme(protocol_counts, country_counts, keywords, logger)

    logger.info("="*50)
    logger.info("🎉 تمام مراحل با موفقیت انجام شد. برنامه به پایان رسید.")
    logger.info("="*50)

if __name__ == "__main__":
    asyncio.run(main())
