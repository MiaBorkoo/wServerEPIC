from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session

from app.schemas.users import UserSaltsResponse
from app.db import crud
from app.db.database import get_db

router = APIRouter()

@router.get("/{username}/salts", response_model=UserSaltsResponse)
def get_salts(username: str, db: Session = Depends(get_db)):
    salts = crud.get_user_salts(db, username)
    if not salts:
        raise HTTPException(status_code=404, detail="User not found")
    return salts 