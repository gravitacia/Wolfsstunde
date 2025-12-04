import secrets
import bcrypt
import jwt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from core.config import Config
from utils.logger import get_logger
from utils.exceptions import SecurityError, ValidationError

logger = get_logger("##############Security##############")


def hash_password(password: str) -> str:
    if not password or not isinstance(password, str):
        msg = "[-] Password must be a non-empty string"
        logger.error(msg)
        raise ValidationError(msg)
    
    try:
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        logger.info("[+] Password hashed successfully")
        return hashed.decode('utf-8')
    except Exception as e:
        msg = f"[-] Password hashing failed: {e}"
        logger.error(msg)
        raise SecurityError(msg)


def verify_password(password: str, password_hash: str) -> bool:
    if not password or not isinstance(password, str):
        logger.warning("[-] Invalid password provided for verification")
        return False
    
    if not password_hash or not isinstance(password_hash, str):
        logger.warning("[-] Invalid password hash provided for verification")
        return False
    
    try:
        is_valid = bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        if is_valid:
            logger.info("[+] Password verification successful")
        else:
            logger.warning("[-] Password verification failed")
        return is_valid
    except Exception as e:
        msg = f"[-] Password verification error: {e}"
        logger.error(msg)
        return False


def generate_jwt_token(user_id: str, expires_in: int = 86400) -> str:
    if not user_id:
        msg = "[-] User ID is required for JWT generation"
        logger.error(msg)
        raise ValidationError(msg)
    
    try:
        Config.load()
        jwt_secret = Config.get("JWT_SECRET", required=True)
        
        if not jwt_secret:
            msg = "[-] JWT_SECRET not configured"
            logger.error(msg)
            raise SecurityError(msg)
        
        payload = {
            'user_id': str(user_id),
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(seconds=expires_in)
        }
        
        token = jwt.encode(payload, jwt_secret, algorithm='HS256')
        logger.info(f"[+] JWT token generated for user {user_id}")
        return token
    except jwt.PyJWTError as e:
        msg = f"[-] JWT generation failed: {e}"
        logger.error(msg)
        raise SecurityError(msg)
    except Exception as e:
        msg = f"[-] JWT generation error: {e}"
        logger.error(msg)
        raise SecurityError(msg)


def verify_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    if not token or not isinstance(token, str):
        logger.warning("[-] Invalid token provided for verification")
        return None
    
    try:
        Config.load()
        jwt_secret = Config.get("JWT_SECRET", required=True)
        
        if not jwt_secret:
            msg = "[-] JWT_SECRET not configured"
            logger.error(msg)
            raise SecurityError(msg)
        
        payload = jwt.decode(token, jwt_secret, algorithms=['HS256'])
        logger.info(f"[+] JWT token verified for user {payload.get('user_id')}")
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("[-] JWT token has expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"[-] Invalid JWT token: {e}")
        return None
    except Exception as e:
        msg = f"[-] JWT verification error: {e}"
        logger.error(msg)
        return None


def generate_api_key() -> str:
    api_key = secrets.token_hex(32)
    logger.info("[+] API key generated successfully")
    return api_key


class RateLimiter:
    def __init__(self, redis_url: Optional[str] = None, default_limit: int = 100, window_seconds: int = 60):
        self.default_limit = default_limit
        self.window_seconds = window_seconds
        self.redis_client = None
        
        try:
            import redis
            Config.load()
            redis_url = redis_url or Config.get("REDIS_URL") or "redis://localhost:6379/0"
            
            try:
                self.redis_client = redis.from_url(redis_url, decode_responses=True)
                self.redis_client.ping()
                logger.info(f"[+] Rate limiter connected to Redis at {redis_url}")
            except redis.ConnectionError as e:
                logger.warning(f"[!] Redis connection failed: {e}. Rate limiting disabled.")
                self.redis_client = None
        except ImportError:
            logger.warning("[!] Redis library not installed. Rate limiting disabled.")
            self.redis_client = None
    
    def is_allowed(self, identifier: str, limit: Optional[int] = None) -> bool:
        if not self.redis_client:
            return True
        
        limit = limit or self.default_limit
        key = f"rate_limit:{identifier}"
        
        try:
            current = self.redis_client.get(key)
            
            if current is None:
                self.redis_client.setex(key, self.window_seconds, "1")
                return True
            
            current_count = int(current)
            
            if current_count >= limit:
                logger.warning(f"[-] Rate limit exceeded for {identifier}: {current_count}/{limit}")
                return False
            
            self.redis_client.incr(key)
            return True
        except Exception as e:
            logger.error(f"[-] Rate limiting error for {identifier}: {e}")
            return True
    
    def reset(self, identifier: str) -> None:
        if not self.redis_client:
            return
        
        key = f"rate_limit:{identifier}"
        try:
            self.redis_client.delete(key)
            logger.info(f"[+] Rate limit reset for {identifier}")
        except Exception as e:
            logger.error(f"[-] Failed to reset rate limit for {identifier}: {e}")
    
    def get_remaining(self, identifier: str, limit: Optional[int] = None) -> int:
        if not self.redis_client:
            return limit or self.default_limit
        
        limit = limit or self.default_limit
        key = f"rate_limit:{identifier}"
        
        try:
            current = self.redis_client.get(key)
            if current is None:
                return limit
            
            current_count = int(current)
            remaining = max(0, limit - current_count)
            return remaining
        except Exception as e:
            logger.error(f"[-] Failed to get remaining requests for {identifier}: {e}")
            return limit

