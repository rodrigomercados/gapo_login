# Database session management
# app/db/session.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.config import settings

#DATABASE_URL = "postgresql+asyncpg://rmercado:rm1802@190.114.255.158/camiones"
#DATABASE_URL = "postgresql+asyncpg://postgres:postgres@45.236.131.81/camiones"
engine = create_engine(settings.DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
