import random
import string
import datetime

def generate_id(length: int = 16) -> str:
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def sanitize_string(input_string: str) -> str:
    return ''.join(c for c in input_string if c.isalnum() or c in (' ', '_', '-')).rstrip()

def validate_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        num = int(part)
        if num < 0 or num > 255:
            return False
    return True

def validate_ipv6(ip: str) -> bool:
    if ip.count("::") > 1:
        return False
    parts = ip.split(":")
    if "" in parts:
        parts = [p for p in parts if p]
    if len(parts) > 8:
        return False
    return all(0 < len(p) <= 4 and all(c in "0123456789abcdefABCDEF" for c in p) for p in parts)

def validate_port(port: int) -> bool:
    return 0 <= port <= 65535

def get_timestamp():
    return datetime.now
    
def format_bytes(bytes):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if bytes < 1024:
            return f"{bytes:.2f} {unit}"
        bytes /= 1024

def chunk_list(items, size):
    if size <= 0:
        raise ValueError("Size must be a positive integer.")
    return [items[i:i + size] for i in range(0, len(items), size)]