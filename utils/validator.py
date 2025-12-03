from . import helpers
import re
import html


def validate_id(id: str, length: int = 16) -> bool:
    if not isinstance(id, str):
        return False
    if len(id) != length:
        return False
    if not id.isalnum():
        return False
    return True

def validate_module(module: str) -> bool:
    if not isinstance(module, str) or not module:
        return False
    allowed= set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
    return all(c in allowed for c in module)

def validate_task(task: str) -> bool:
    if not isinstance(task, str) or not task.strip():
        return False
    if len(task) > 128:
        return False
    return True

def sanitize_input(input_str: str) -> str:
    if not isinstance(input_str, str): return ""
    sanitized = html.escape(input_str.strip())
    return re.sub(r'\s+', ' ', re.sub(r'[;|&$`\\\'"]', '', sanitized))


##TODO
def validate_config():
    return 0