# Main application entry point
# app/main.py
from fastapi import FastAPI
from app.api.api import router as api_router
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],           # "URLs de los frntends permitidos"
    allow_credentials=True,
    allow_methods=["*"],        #Métodos permitidos
    allow_headers=["*"],        #Cabeceras permitidas
)

app.include_router(api_router)
#app.include_router(user_router)