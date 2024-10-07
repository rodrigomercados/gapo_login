# Token schemas
# app/schemas/token.py
from pydantic import BaseModel
from typing import List


class UrlInfo(BaseModel):
    cod_informe: int
    desc_informe: str
    cod_tipo_usuario: int
    url: str

class Token(BaseModel):
    access_token: str
    token_type: str
    cod_usuario: int
    desc_usuario: str
    cod_tipo_usuario: int
    cod_plataforma: int
    desc_plataforma: str
    urls_usuario: List[UrlInfo]

class TokenData(BaseModel):
    desc_usuario: str | None = None

