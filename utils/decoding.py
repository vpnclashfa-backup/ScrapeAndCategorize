# مسیر: utils/decoding.py

import base64

def decode_base64_content(data: str) -> str | None:
    """
    یک رشته Base64 را دیکود می‌کند. برای URL ها و محتوای کانفیگ استفاده می‌شود.
    """
    try:
        # پدینگ (padding) را برای اطمینان از صحت دیکود اضافه می‌کند
        data = data.replace('_', '/').replace('-', '+')
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8')
    except (ValueError, TypeError, base64.binascii.Error):
        # در صورت بروز خطا در دیکود، None برمی‌گرداند
        return None
