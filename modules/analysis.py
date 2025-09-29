# modules/analysis.py
import json
from typing import Any, Dict

def load_analysis_field(value) -> Dict:
    if not value:
        return {}
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value)
    except Exception:
        return {}


def dump_analysis_field(obj: Any) -> str:
    try:
        return json.dumps(obj)
    except Exception:
        return json.dumps({})