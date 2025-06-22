# مسیر: core/parser.py

import re
import json
from typing import Dict, Set
from urllib.parse import unquote, parse_qs
from utils.decoding import decode_url_safe_base64
from config import settings

def _get_config_name(config: str) -> str | None:
    """یک نام از داخل رشته کانفیگ استخراج می‌کند."""
    if '#' in config:
        try:
            name = config.split('#', 1)[1]
            return unquote(name).strip()
        except IndexError:
            pass
    if config.startswith("vmess://"):
        try:
            b64_part = config[8:]
            decoded_str = decode_url_safe_base64(b64_part)
            if decoded_str:
                return json.loads(decoded_str).get('ps')
        except: return None
    elif config.startswith("ssr://"):
        try:
            b64_part = config[6:]
            decoded_str = decode_url_safe_base64(b64_part)
            if not decoded_str: return None
            params_str = decoded_str.split('/?')[1]
            params = parse_qs(params_str)
            if 'remarks' in params and params['remarks']:
                return decode_url_safe_base64(params['remarks'][0])
        except: return None
    return None

def analyze_content(content: str, all_keywords: Dict) -> Dict:
    """
    محتوای متنی را تحلیل کرده و کانفیگ‌ها را به تفکیک پروتکل و کشور برمی‌گرداند.
    """
    # استخراج کلمات کلیدی و الگوهای لازم
    protocol_patterns = {p: all_keywords.get(p, []) for p in settings.PROTOCOL_CATEGORIES}
    country_names = [k for k in all_keywords if k not in settings.PROTOCOL_CATEGORIES]

    # پیدا کردن تمام کانفیگ‌ها بر اساس پروتکل
    protocol_configs: Dict[str, Set[str]] = {p: set() for p in settings.PROTOCOL_CATEGORIES}
    all_found_configs: Set[str] = set()

    for protocol, patterns in protocol_patterns.items():
        for pattern_str in patterns:
            try:
                found = re.findall(pattern_str, content, re.IGNORECASE)
                for config in found:
                    protocol_configs[protocol].add(config.strip())
            except re.error:
                continue
    
    for configs in protocol_configs.values():
        all_found_configs.update(configs)

    # دسته‌بندی کانفیگ‌ها بر اساس کشور
    country_configs: Dict[str, Set[str]] = {c: set() for c in country_names}
    for config in all_found_configs:
        name = _get_config_name(config)
        if not name:
            continue
        
        name_lower = name.lower()
        for country in country_names:
            country_keywords = [kw.lower() for kw in all_keywords.get(country, [])]
            if any(kw in name_lower for kw in country_keywords):
                country_configs[country].add(config)
                break # برای جلوگیری از تخصیص یک کانفیگ به چند کشور

    # تولید آمار برای لاگ
    stats = {
        'total': len(all_found_configs),
        'iran_count': len(country_configs.get("Iran", set())),
        'protocols': {p: len(c) for p, c in protocol_configs.items() if c}
    }

    return {
        'stats': stats,
        'protocol_configs': protocol_configs,
        'country_configs': country_configs
    }
