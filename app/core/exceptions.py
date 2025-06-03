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

# Additional secure error handlers
def handle_validation_error(e: Exception) -> HTTPException:
    logger.error(f"Validation error: {str(e)}")
    return SecureHTTPException(
        status_code=400,
        detail="Invalid input provided",
        internal_detail=str(e)
    )

def handle_authentication_error(e: Exception) -> HTTPException:
    logger.error(f"Authentication error: {str(e)}")
    return SecureHTTPException(
        status_code=401,
        detail="Authentication failed",
        internal_detail=str(e)
    )

def handle_authorization_error(e: Exception) -> HTTPException:
    logger.error(f"Authorization error: {str(e)}")
    return SecureHTTPException(
        status_code=403,
        detail="Access denied",
        internal_detail=str(e)
    )

def handle_file_operation_error(e: Exception) -> HTTPException:
    logger.error(f"File operation error: {str(e)}")
    return SecureHTTPException(
        status_code=500,
        detail="File operation failed",
        internal_detail=str(e)
    )

def handle_generic_error(e: Exception) -> HTTPException:
    logger.error(f"Generic error: {str(e)}")
    return SecureHTTPException(
        status_code=500,
        detail="An unexpected error occurred",
        internal_detail=str(e)
    ) 

