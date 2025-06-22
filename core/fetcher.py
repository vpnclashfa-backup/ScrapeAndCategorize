# مسیر: core/fetcher.py

import aiohttp
from logging import Logger
from utils.decoding import decode_base64_content
from config import settings
from bs4 import BeautifulSoup

async def fetch_and_normalize_content(session: aiohttp.ClientSession, url: str, is_base64_content: bool, logger: Logger) -> tuple[str, str | None]:
    """
    محتوای یک URL را دریافت و نرمال‌سازی می‌کند و رویدادها را لاگ می‌زند.
    """
    try:
        logger.info(f"درحال ارسال درخواست به {url} ...")
        async with session.get(url, timeout=settings.REQUEST_TIMEOUT) as response:
            response.raise_for_status()
            raw_content = await response.text()

            if is_base64_content:
                decoded_configs = decode_base64_content(raw_content.strip())
                if decoded_configs:
                    logger.info(f"محتوای Base64 از {url} با موفقیت دیکود شد.")
                    return url, decoded_configs
                else:
                    logger.warning(f"دیکود محتوای Base64 از {url} ناموفق بود.")
                    return url, None
            else:
                soup = BeautifulSoup(raw_content, 'html.parser')
                text_content = ""
                for element in soup.find_all(['pre', 'code', 'p', 'div', 'li', 'span', 'td']):
                    text_content += element.get_text(separator='\n', strip=True) + "\n"
                
                if not text_content.strip():
                     text_content = soup.get_text(separator='\n', strip=True)
                
                logger.info(f"محتوای متنی از {url} با موفقیت استخراج شد.")
                return url, text_content

    except aiohttp.ClientError as e:
        logger.error(f"خطا در اتصال به {url}: {e}")
        return url, None
    except Exception as e:
        logger.error(f"خطای نامشخص در پردازش {url}: {e}")
        return url, None
