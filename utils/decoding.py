# مسیر: utils/decoding.py

import base64

def decode_base64_content(data: str) -> str | None:
    """
    یک رشته Base64 استاندارد را دیکود می‌کند.
    برای دیکود کردن محتوای کامل یک صفحه استفاده می‌شود.
    """
    try:
        # پدینگ (padding) را برای اطمینان از صحت دیکود اضافه می‌کند
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8')
    except (ValueError, TypeError, base64.binascii.Error):
        return None

def decode_url_safe_base64(data: str) -> str | None:
    """
    یک رشته Base64 که با فرمت URL-safe کد شده را دیکود می‌کند.
    برای استخراج نام کانفیگ‌های Vmess و SSR استفاده می‌شود.
    """
    try:
        # جایگزینی کاراکترهای URL-safe با معادل استاندارد Base64
        data = data.replace('_', '/').replace('-', '+')
        # پدینگ (padding) را برای اطمینان از صحت دیکود اضافه می‌کند
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8')
    except (ValueError, TypeError, base64.binascii.Error):
        return None
