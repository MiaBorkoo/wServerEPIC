from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import os
import ssl
from dotenv import load_dotenv

load_dotenv()

from app.core.config import DATABASE_URL, ENVIRONMENT

# Database SSL configuration
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
        # PostgreSQL configuration with SSL
        connect_args = {}
        
        if ENVIRONMENT in ["production", "staging"]:
            # Create SSL context for database connections
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False  # Adjust based on your setup
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            
            connect_args["sslmode"] = "require"
            connect_args["sslcontext"] = ssl_context
        
        return create_engine(
            DATABASE_URL,
            pool_pre_ping=True,
            pool_recycle=300,
            connect_args=connect_args,
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