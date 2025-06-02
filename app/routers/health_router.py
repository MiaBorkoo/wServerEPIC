from fastapi import APIRouter
from app.core.security import check_time_sync

router = APIRouter()

@router.get("/time-sync")
async def check_time_synchronization():
    """Check if server time is synchronized with NTP servers"""
    return check_time_sync() 