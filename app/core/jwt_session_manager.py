from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from jose import jwt, JWTError
from fastapi import HTTPException, status
import secrets
import os
import threading
import time
import logging

# Environment variables
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

class JWTSessionManager:
    """JWT-based session manager"""
    
    def __init__(self):
        self.secret_key = SECRET_KEY
        self.algorithm = ALGORITHM
        self.access_token_expiry = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        self.refresh_token_expiry = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        
        # For tracking revoked tokens with TTL to prevent memory growth
        self.revoked_tokens = {}  # {token_hash: expiry_timestamp}
        self.lock = threading.Lock()
        
        # Cleanup old revoked tokens every hour
        self._last_cleanup = time.time()
        self._cleanup_interval = 3600  # 1 hour
    
    def _cleanup_revoked_tokens(self):
        """Clean up expired revoked tokens to prevent memory growth"""
        current_time = time.time()
        
        # Only cleanup if enough time has passed
        if current_time - self._last_cleanup < self._cleanup_interval:
            return
            
        with self.lock:
            expired_tokens = [
                token for token, expiry in self.revoked_tokens.items() 
                if current_time > expiry
            ]
            
            for token in expired_tokens:
                del self.revoked_tokens[token]
                
            self._last_cleanup = current_time
            
            if expired_tokens:
                logging.info(f"Cleaned up {len(expired_tokens)} expired revoked tokens")
    
    def _get_token_hash(self, token: str) -> str:
        """Get a hash of the token for storage (saves memory)"""
        import hashlib
        return hashlib.sha256(token.encode()).hexdigest()
    
    def create_session(self, username: str, data: Dict[str, Any] = None) -> Dict[str, str]:
        """Create JWT access and refresh tokens"""
        now = datetime.now(timezone.utc)
        
        # Create access token payload
        access_payload = {
            "sub": username,  # Subject (username)
            "iat": now,       # Issued at
            "exp": now + self.access_token_expiry,  # Expires
            "type": "access",
            "session_id": secrets.token_urlsafe(16),  # Unique session identifier
            "data": data or {}
        }
        
        # Create refresh token payload
        refresh_payload = {
            "sub": username,
            "iat": now,
            "exp": now + self.refresh_token_expiry,
            "type": "refresh",
            "session_id": access_payload["session_id"]
        }
        
        access_token = jwt.encode(access_payload, self.secret_key, algorithm=self.algorithm)
        refresh_token = jwt.encode(refresh_payload, self.secret_key, algorithm=self.algorithm)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": int(self.access_token_expiry.total_seconds())
        }
    
    def get_session(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate and decode JWT token"""
        try:
            # Clean up expired revoked tokens periodically
            self._cleanup_revoked_tokens()
            
            # Check if token is revoked
            token_hash = self._get_token_hash(token)
            with self.lock:
                if token_hash in self.revoked_tokens:
                    return None
            
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Verify token type
            if payload.get("type") != "access":
                return None
            
            # Check expiration (jwt.decode already does this, but let's be explicit)
            now = datetime.now(timezone.utc)
            exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
            
            if now > exp:
                return None
            
            return {
                "username": payload["sub"],
                "session_id": payload["session_id"],
                "created_at": datetime.fromtimestamp(payload["iat"], tz=timezone.utc).isoformat(),
                "expires_at": exp.isoformat(),
                "data": payload.get("data", {})
            }
            
        except JWTError:
            return None
    
    def refresh_session(self, refresh_token: str) -> Optional[Dict[str, str]]:
        """Create new access token using refresh token"""
        try:
            token_hash = self._get_token_hash(refresh_token)
            with self.lock:
                if token_hash in self.revoked_tokens:
                    return None
            
            payload = jwt.decode(refresh_token, self.secret_key, algorithms=[self.algorithm])
            
            # Verify it's a refresh token
            if payload.get("type") != "refresh":
                return None
            
            username = payload["sub"]
            session_id = payload["session_id"]
            
            # Create new access token
            now = datetime.now(timezone.utc)
            access_payload = {
                "sub": username,
                "iat": now,
                "exp": now + self.access_token_expiry,
                "type": "access",
                "session_id": session_id,
                "data": {}  # Could store user data here if needed
            }
            
            access_token = jwt.encode(access_payload, self.secret_key, algorithm=self.algorithm)
            
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": int(self.access_token_expiry.total_seconds())
            }
            
        except JWTError:
            return None
    
    def delete_session(self, token: str) -> bool:
        """Revoke a token (logout)"""
        try:
            # Decode token to get expiry time
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            expiry_timestamp = payload["exp"]
            
            token_hash = self._get_token_hash(token)
            with self.lock:
                self.revoked_tokens[token_hash] = expiry_timestamp
            
            return True
        except JWTError:
            return False
    
    # def invalidate_user_sessions(self, username: str) -> int:
    #     """Invalidate all sessions for a user - limited functionality with JWT
        
    #     Note: With JWT, we can't easily invalidate all user sessions. This would require either:
    #     1. A blacklist of all tokens (memory intensive)
    #     2. Changing the user's secret key (database change)
    #     3. Adding a "issued_after" timestamp to user record
        
    #     This method is not fully implemented. Consider using an alternative strategy for session management
    #     if you need to invalidate all user sessions.
    #     """
    #     logging.warning(f"invalidate_user_sessions called for {username} but is not fully implemented with JWT")
    #     raise NotImplementedError(
    #         "invalidate_user_sessions is not supported with the current JWT implementation. "
    #         "Consider implementing a user-specific token versioning system or switching to stateful sessions."
    #     )
    
    def validate_and_extract_user(self, token: str) -> Optional[str]:
        """Extract username from valid token"""
        session = self.get_session(token)
        return session["username"] if session else None 