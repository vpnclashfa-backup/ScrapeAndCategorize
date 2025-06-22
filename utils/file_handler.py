# مسیر: utils/file_handler.py

import os
import json
from typing import List, Dict

def read_urls_from_file(file_path: str) -> List[str]:
    """
    تمام خطوط غیرخالی یک فایل متنی را می‌خواند و به صورت لیست برمی‌گرداند.
    """
    if not os.path.exists(file_path):
        return []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return []

def load_keywords(file_path: str) -> Dict:
    """
    فایل JSON کلمات کلیدی را می‌خواند و به صورت دیکشنری برمی‌گرداند.
    """
    if not os.path.exists(file_path):
        return {}
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"Error reading or parsing keywords file {file_path}: {e}")
        return {}
