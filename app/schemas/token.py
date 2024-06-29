# Token schemas
# app/schemas/token.py
from pydantic import BaseModel
from typing import List

class Token(BaseModel):
    access_token: str
    token_type: str
    desc_usuario: str
    cod_tipo_usuario: int
    urls_usuario: List[str]

class TokenData(BaseModel):
    desc_usuario: str | None = None

