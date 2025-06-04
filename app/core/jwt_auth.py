from fastapi import HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import Optional

from app.core.jwt_session_manager import JWTSessionManager
from app.db.database import get_db
from app.db import crud

# Initialize JWT session manager
jwt_session_manager = JWTSessionManager()

# HTTP Bearer token scheme
security = HTTPBearer()

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """Get current authenticated user from JWT token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Validate JWT token
        session = jwt_session_manager.get_session(credentials.credentials)
        if not session:
            raise credentials_exception
        
        username = session["username"]
        
        # Get user from database
        user = crud.get_user_by_username(db, username=username)
        if user is None:
            raise credentials_exception
            
        return user
        
    except Exception:
        raise credentials_exception

async def get_current_user_optional(
    request: Request,
    db: Session = Depends(get_db)
) -> Optional[any]:
    """Get current user if token is provided, otherwise return None"""
    authorization = request.headers.get("Authorization")
    
    if not authorization or not authorization.startswith("Bearer "):
        return None
    
    token = authorization.split(" ")[1]
    
    try:
        session = jwt_session_manager.get_session(token)
        if not session:
            return None
        
        username = session["username"]
        user = crud.get_user_by_username(db, username=username)
        return user
        
    except Exception:
        return None

async def require_authenticated_user(current_user = Depends(get_current_user)):
    """Dependency that requires authenticated user"""
    return current_user

def get_user_from_token(token: str, db: Session) -> Optional[any]:
    """Extract user from token (utility function)"""
    try:
        session = jwt_session_manager.get_session(token)
        if not session:
            return None
        
        username = session["username"]
        return crud.get_user_by_username(db, username=username)
        
    except Exception:
        return None 