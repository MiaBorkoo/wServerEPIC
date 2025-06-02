from datetime import datetime, timedelta
import redis
import json
from typing import Optional, Dict, Any
from secrets import token_urlsafe

class SessionManager:
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        self.redis = redis.from_url(redis_url)
        self.session_expiry = timedelta(hours=1)  # Default 1 hour expiry
        self.max_sessions_per_user = 5  # Maximum concurrent sessions per user

    def create_session(self, username: str, data: Dict[str, Any] = None) -> str:
        """Create a new session for a user"""
        session_token = token_urlsafe(64)
        session_data = {
            "username": username,
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + self.session_expiry).isoformat(),
            "data": data or {}
        }

        # Check and enforce max sessions per user
        user_sessions = self.get_user_sessions(username)
        if len(user_sessions) >= self.max_sessions_per_user:
            # Remove oldest session
            oldest_session = min(user_sessions.items(), key=lambda x: datetime.fromisoformat(x[1]["created_at"]))[0]
            self.delete_session(oldest_session)

        # Store session data
        self.redis.setex(
            f"session:{session_token}",
            int(self.session_expiry.total_seconds()),
            json.dumps(session_data)
        )

        # Add to user's session list
        self.redis.sadd(f"user_sessions:{username}", session_token)
        return session_token

    def get_session(self, session_token: str) -> Optional[Dict[str, Any]]:
        """Get session data if it exists and is valid"""
        session_data = self.redis.get(f"session:{session_token}")
        if not session_data:
            return None

        data = json.loads(session_data)
        expires_at = datetime.fromisoformat(data["expires_at"])

        if datetime.now() > expires_at:
            self.delete_session(session_token)
            return None

        return data

    def update_session(self, session_token: str, data: Dict[str, Any]) -> bool:
        """Update session data and extend expiry"""
        current_session = self.get_session(session_token)
        if not current_session:
            return False

        current_session["data"].update(data)
        current_session["expires_at"] = (datetime.now() + self.session_expiry).isoformat()

        self.redis.setex(
            f"session:{session_token}",
            int(self.session_expiry.total_seconds()),
            json.dumps(current_session)
        )
        return True

    def delete_session(self, session_token: str) -> bool:
        """Delete a session"""
        session_data = self.get_session(session_token)
        if session_data:
            username = session_data["username"]
            self.redis.delete(f"session:{session_token}")
            self.redis.srem(f"user_sessions:{username}", session_token)
            return True
        return False

    def get_user_sessions(self, username: str) -> Dict[str, Dict[str, Any]]:
        """Get all active sessions for a user"""
        session_tokens = self.redis.smembers(f"user_sessions:{username}")
        sessions = {}
        for token in session_tokens:
            token_str = token.decode('utf-8')
            session_data = self.get_session(token_str)
            if session_data:  # Only include valid sessions
                sessions[token_str] = session_data
        return sessions

    def invalidate_user_sessions(self, username: str) -> int:
        """Invalidate all sessions for a user"""
        session_tokens = self.redis.smembers(f"user_sessions:{username}")
        count = 0
        for token in session_tokens:
            if self.delete_session(token.decode('utf-8')):
                count += 1
        return count 