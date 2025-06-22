# مسیر: core/parser.py

import re
import json
from typing import Dict, List, Set
from urllib.parse import unquote, parse_qs
from utils.decoding import decode_url_safe_base64
from config import settings

def _get_config_name(config: str) -> str | None:
    """یک نام از داخل رشته کانفیگ استخراج می‌کند."""
    # روش اول: استخراج نام بعد از علامت #
    if '#' in config:
        try:
            name = config.split('#', 1)[1]
            return unquote(name).strip()
        except IndexError:
            pass

    # روش‌های خاص برای هر پروتکل
    if config.startswith("vmess://"):
        try:
            b64_part = config[8:]
            decoded_str = decode_url_safe_base64(b64_part)
            if decoded_str:
                return json.loads(decoded_str).get('ps')
        except:
            return None
    elif config.startswith("ssr://"):
        try:
            b64_part = config[6:]
            decoded_str = decode_url_safe_base64(b64_part)
            if not decoded_str: return None
            params_str = decoded_str.split('/?')[1]
            params = parse_qs(params_str)
            if 'remarks' in params and params['remarks']:
                return decode_url_safe_base64(params['remarks'][0])
        except:
            return None
            
    return None

def analyze_content(content: str, all_keywords: Dict) -> Dict:
    """
    محتوای متنی را تحلیل کرده و آمار کانفیگ‌ها را برمی‌گرداند.
    """
    stats = {
        'total': 0,
        'iran_count': 0,
        'protocols': {}
    }
    
    # استخراج کلمات کلیدی و الگوهای لازم
    protocol_patterns = {
        proto: all_keywords.get(proto, []) 
        for proto in settings.PROTOCOL_CATEGORIES
    }
    iran_keywords = [kw.lower() for kw in all_keywords.get("Iran", [])]
    
    all_found_configs: Set[str] = set()
    
    # پیدا کردن تمام کانفیگ‌ها بر اساس پروتکل
    for protocol, patterns in protocol_patterns.items():
        protocol_configs: Set[str] = set()
        for pattern_str in patterns:
            try:
                found = re.findall(pattern_str, content, re.IGNORECASE)
                for config in found:
                    # TODO: فیلترهای کانفیگ نامعتبر را اینجا اضافه کنید
                    protocol_configs.add(config.strip())
            except re.error:
                continue # از الگوهای regex نامعتبر رد شو
        
        if protocol_configs:
            stats['protocols'][protocol] = len(protocol_configs)
            all_found_configs.update(protocol_configs)

    stats['total'] = len(all_found_configs)

    # شمارش کانفیگ‌های ایران
    iran_count = 0
    if iran_keywords:
        for config in all_found_configs:
            name = _get_config_name(config)
            if name:
                name_lower = name.lower()
                if any(kw in name_lower for kw in iran_keywords):
                    iran_count += 1
    stats['iran_count'] = iran_count

    return stats
