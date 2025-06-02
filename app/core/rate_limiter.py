from datetime import datetime, timedelta
import redis
from typing import Optional, Dict, Any

class RateLimiter:
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        self.redis = redis.from_url(redis_url)
        
        # Default limits
        self.default_limits = {
            "login": {"count": 5, "window": 300},   
            "register": {"count": 3, "window": 3600},  
            "totp": {"count": 3, "window": 300},  
            "api": {"count": 100, "window": 60}  
        }

    def is_rate_limited(self, key: str, limit_type: str = "api") -> bool:
        """Check if a key has exceeded its rate limit"""
        now = datetime.now().timestamp()
        window = self.default_limits[limit_type]["window"]
        max_count = self.default_limits[limit_type]["count"]
        
        # Create a key that includes the limit type and user identifier
        redis_key = f"ratelimit:{limit_type}:{key}"
        
        # Get current count
        count = self.redis.zcount(redis_key, now - window, now)
        
        if count >= max_count:
            return True
            
        # Add current timestamp to sorted set
        self.redis.zadd(redis_key, {str(now): now})
        
        # Remove old entries
        self.redis.zremrangebyscore(redis_key, 0, now - window)
        
        # Set expiry on the key
        self.redis.expire(redis_key, window)
        
        return False

    def get_remaining_attempts(self, key: str, limit_type: str = "api") -> Dict[str, Any]:
        """Get remaining attempts and time until reset"""
        now = datetime.now().timestamp()
        window = self.default_limits[limit_type]["window"]
        max_count = self.default_limits[limit_type]["count"]
        redis_key = f"ratelimit:{limit_type}:{key}"
        
        # Get current count
        count = self.redis.zcount(redis_key, now - window, now)
        
        # Get oldest timestamp in the window
        oldest = self.redis.zrange(redis_key, 0, 0, withscores=True)
        reset_time = (oldest[0][1] + window) if oldest else (now + window)
        
        return {
            "remaining": max(0, max_count - count),
            "reset_in": int(reset_time - now),
            "total": max_count,
            "window_seconds": window
        } 