from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session

from app.schemas.users import UserSaltsResponse
from app.db import crud
from app.db.database import get_db
from app.core.exceptions import handle_database_error, SecureHTTPException

router = APIRouter()

@router.get("/{username}/salts", response_model=UserSaltsResponse)
def get_salts(username: str, db: Session = Depends(get_db)):
    try:
        salts = crud.get_user_salts(db, username)
        if not salts:
            raise SecureHTTPException(
                status_code=404, 
                detail="User not found",
                internal_detail=f"No salts found for user: {username}"
            )
        return salts
    except HTTPException:
        raise
    except Exception as e:
        raise handle_database_error(e) 
    