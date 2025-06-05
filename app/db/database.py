from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import os
from dotenv import load_dotenv

load_dotenv()

from app.core.config import DATABASE_URL, ENVIRONMENT

# Check if we should echo the SQL queries - never in production 
def should_echo_sql():
    if os.getenv("ENVIRONMENT") == "production":
        return False
    return os.getenv("SQL_DEBUG", "false").lower() == "true"

echo=should_echo_sql()

# Database configuration
def get_database_engine():
    if DATABASE_URL.startswith("sqlite"):
        # SQLite specific configuration
        return create_engine(
            DATABASE_URL,
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
            echo=echo
        )
    elif DATABASE_URL.startswith("mysql"):
        # MySQL specific configuration
        return create_engine(
            DATABASE_URL,
            pool_pre_ping=True,
            pool_recycle=3600,  # MySQL connections can be longer-lived
            pool_size=10,
            max_overflow=20,
            echo=echo
        )
    else:
        # PostgreSQL configuration
        return create_engine(
            DATABASE_URL,
            pool_pre_ping=True,
            pool_recycle=300,
            echo=echo
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