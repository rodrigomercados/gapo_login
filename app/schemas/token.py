# Token schemas
# app/schemas/token.py
from pydantic import BaseModel
from typing import List


class UrlInfo(BaseModel):
    cod_informe: int
    desc_informe: str
    url: str

class Token(BaseModel):
    access_token: str
    token_type: str
    desc_usuario: str
    cod_tipo_usuario: int
    urls_usuario: List[UrlInfo]

class TokenData(BaseModel):
    desc_usuario: str | None = None

