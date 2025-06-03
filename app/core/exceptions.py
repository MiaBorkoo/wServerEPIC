import logging
from fastapi import HTTPException
from typing import Dict, Any

logger = logging.getLogger(__name__)
# Custom HTTPException class to handle secure errors, so we don't expose internal details to the client
class SecureHTTPException(HTTPException):
    def __init__(self, status_code: int, detail: str, internal_detail: str = None):
        super().__init__(status_code=status_code, detail=detail)
        if internal_detail:
            logger.error(f"Internal error: {internal_detail}")

def handle_database_error(e: Exception) -> HTTPException:
    logger.error(f"Database error: {str(e)}")
    return SecureHTTPException(
        status_code=500,
        detail="Internal server error",
        internal_detail=str(e)
    ) 