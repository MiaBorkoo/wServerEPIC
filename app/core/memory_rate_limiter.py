from datetime import datetime, timedelta
import time
from typing import Optional, Dict, Any, Tuple
import threading
from collections import defaultdict, deque
from app.core.config import RATE_LIMITS, DEFAULT_RATE_LIMIT

class MemoryRateLimiter:
    """In-memory rate limiter """
    
    def __init__(self):
        self.storage = defaultdict(deque)
        self.lock = threading.Lock()
        
        # Rate limiting rules from config
        self.limits = RATE_LIMITS

    def is_rate_limited(self, identifier: str, action: str) -> bool:
        """Check if the identifier is rate limited for the given action"""
        max_attempts, window = self.limits.get(action, DEFAULT_RATE_LIMIT)
        
        with self.lock:
            key = f"{action}:{identifier}"
            now = time.time()
            
            # Clean old entries outside the window
            while self.storage[key] and now - self.storage[key][0] > window:
                self.storage[key].popleft()
            
            # Check if rate limited
            if len(self.storage[key]) >= max_attempts:
                return True
            
            # Add current attempt
            self.storage[key].append(now)
            return False

    def get_remaining_attempts(self, identifier: str, action: str) -> Dict[str, Any]:
        """Get remaining attempts for identifier"""
        max_attempts, window = self.limits.get(action, DEFAULT_RATE_LIMIT)
        
        with self.lock:
            key = f"{action}:{identifier}"
            now = time.time()
            
            # Clean old entries
            while self.storage[key] and now - self.storage[key][0] > window:
                self.storage[key].popleft()
            
            current_attempts = len(self.storage[key])
            remaining = max(0, max_attempts - current_attempts)
            
            # Calculate reset time
            reset_in = 0
            if self.storage[key]:
                oldest_attempt = self.storage[key][0]
                reset_in = max(0, window - (now - oldest_attempt))
            
            return {
                "remaining": remaining,
                "reset_in": int(reset_in),
                "max_attempts": max_attempts,
                "window": window
            }
    
    def reset_user_limits(self, identifier: str, action: str = None) -> bool:
        """Reset rate limits for a user (admin function)"""
        with self.lock:
            if action:
                key = f"{action}:{identifier}"
                if key in self.storage:
                    del self.storage[key]
                    return True
            else:
                # Reset all actions for user
                keys_to_delete = [k for k in self.storage.keys() if k.endswith(f":{identifier}")]
                for key in keys_to_delete:
                    del self.storage[key]
                return len(keys_to_delete) > 0
        return False
    
    def get_user_status(self, identifier: str) -> Dict[str, Any]:
        """Get rate limiting status for all actions for a user"""
        status = {}
        for action in self.limits.keys():
            status[action] = self.get_remaining_attempts(identifier, action)
        return status
    
    def cleanup_old_entries(self):
        """Cleanup old entries to prevent memory leaks"""
        with self.lock:
            now = time.time()
            keys_to_delete = []
            
            for key, timestamps in self.storage.items():
                # Get the window for this action
                action = key.split(':')[0]
                _, window = self.limits.get(action, DEFAULT_RATE_LIMIT)
                
                # Remove old timestamps
                while timestamps and now - timestamps[0] > window:
                    timestamps.popleft()
                
                # If no timestamps left, mark for deletion
                if not timestamps:
                    keys_to_delete.append(key)
            
            # Delete empty entries
            for key in keys_to_delete:
                del self.storage[key]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics"""
        with self.lock:
            active_keys = len(self.storage)
            total_entries = sum(len(deque_obj) for deque_obj in self.storage.values())
            
            return {
                "active_identifiers": active_keys,
                "total_tracked_attempts": total_entries,
                "configured_limits": self.limits
            } 