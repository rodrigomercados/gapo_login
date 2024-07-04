# schemas

from pydantic import BaseModel
from datetime import date

class Auditoria_AccesoResponse(BaseModel):
    desc_auditoria_acceso: str
    fecha: date
    cod_usuario: int
    cod_informe: int

    class Config:
        from_attributes = True

class Auditoria_AccesoCreate(BaseModel):
    desc_auditoria_acceso: str
    fecha: date
    cod_usuario: int
    cod_informe: int

    class Config:
        from_attributes = True


class Auditoria_AccesoUpdate(BaseModel):
    desc_auditoria_acceso: str
    fecha: date
    cod_usuario: int
    cod_informe: int

    class Config:
        from_attributes = True