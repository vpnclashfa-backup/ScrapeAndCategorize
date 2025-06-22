# مسیر: utils/text_helpers.py

def is_persian_like(text: str) -> bool:
    """
    بررسی می‌کند که آیا یک رشته عمدتاً حاوی کاراکترهای فارسی است یا خیر.
    """
    if not isinstance(text, str) or not text.strip():
        return False
    
    persian_char_count = 0
    latin_char_count = 0
    
    for char in text:
        if '\u0600' <= char <= '\u06FF' or char in ['\u200C', '\u200D']:
            persian_char_count += 1
        elif 'a' <= char.lower() <= 'z':
            latin_char_count += 1
            
    # اگر تعداد حروف فارسی بیشتر باشد و حروف لاتین کم یا صفر باشند، فارسی تلقی می‌شود
    return persian_char_count > latin_char_count
