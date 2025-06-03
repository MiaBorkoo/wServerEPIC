from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import os
from dotenv import load_dotenv

load_dotenv()

from app.core.config import DATABASE_URL, ENVIRONMENT

# Database configuration
def get_database_engine():
    if DATABASE_URL.startswith("sqlite"):
        # SQLite specific configuration
        return create_engine(
            DATABASE_URL,
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
            echo=os.getenv("SQL_DEBUG", "false").lower() == "true"
        )
    else:
        # PostgreSQL configuration
        return create_engine(
            DATABASE_URL,
            pool_pre_ping=True,
            pool_recycle=300,
            echo=os.getenv("SQL_DEBUG", "false").lower() == "true"
        )

engine = get_database_engine()

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dependency for FastAPI
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close() 