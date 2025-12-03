import os
import secrets
from dotenv import load_dotenv, set_key, dotenv_values
from pathlib import Path
from utils.exceptions import ValidationError
from utils.logger import get_logger

logger = get_logger("##############Config##############")

class Config:
    ENV_PATH = Path("../.env")

    @classmethod
    def load(cls) -> None:
        if not cls.ENV_PATH.exists():
            logger.warning(f"[!] .env file not found at {cls.ENV_PATH}, creating new one")
            cls.ENV_PATH.touch()  # create empty .env

        try:
            load_dotenv(dotenv_path=str(cls.ENV_PATH))
            logger.info(f"[+] Loaded environment variables from {cls.ENV_PATH}")
        except Exception as e:
            logger.error(f"[-] Failed to load .env: {e}")
            raise ValidationError(f"[-] Failed to load .env file: {e}", code=1002)

        cls._ensure_secret("JWT_SECRET", 32)
        cls._ensure_secret("ENCRYPTION_KEY", 32)
        cls._ensure_admin_password(16)

    @classmethod
    def _ensure_secret(cls, key: str, length: int) -> None:
        value = os.getenv(key)
        if not value or not value.strip():
            value = secrets.token_hex(length)
            set_key(str(cls.ENV_PATH), key, value)
            logger.info(f"[!] Generated missing {key} and saved to .env")

    @classmethod
    def _ensure_admin_password(cls, length: int) -> None:
        password = os.getenv("ADMIN_PASSWORD")
        if not password or not password.strip():
            password = secrets.token_urlsafe(length)
            set_key(str(cls.ENV_PATH), "ADMIN_PASSWORD", password)
            logger.info(f"[!] Generated ADMIN_PASSWORD and saved to .env")

    @staticmethod
    def get(key: str, required: bool = False):
        value = os.getenv(key)
        if required and (value is None or not value.strip()):
            logger.error(f"[!] Missing required environment variable: {key}")
            raise ValidationError(f"[!] Missing required environment variable: {key}", code=1003)
        return value
