# Token schemas
# app/schemas/token.py
from pydantic import BaseModel

class Token(BaseModel):
    access_token: str
    token_type: str
    desc_usuario: str
    cod_tipo_usuario: int

class TokenData(BaseModel):
    desc_usuario: str | None = None

