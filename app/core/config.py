# Configuration settings
# app/core/config.py
from dotenv import load_dotenv
import os

load_dotenv()  # Asegúrate de que esta línea esté al principio para cargar las variables antes de usarlas

class Settings:
    SECRET_KEY: str = os.getenv("SECRET_KEY", "default_secret_key")
    #DATABASE_URL = "postgresql+asyncpg://rmercado:rm1802@190.114.255.158/camiones"
    #DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://postgres:P%40stgr%40s2024@45.236.131.81/camiones")
    #DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost/camiones")
    #DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://rmercado:rm1802@190.114.255.158/camiones")
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost/gapo")
settings = Settings()  # Esta es la instancia de la clase que estás exportando
 
