# schemas

from pydantic import BaseModel
from datetime import date,datetime

class Auditoria_AccesoResponse(BaseModel):
    cod_auditoria_acceso: int
    desc_auditoria_acceso: str
    fecha: datetime
    cod_usuario: int
    run_usuario: str
    nombres_usuario: str
    apellido_paterno_usuario: str
    apellido_materno_usuario: str
    cod_informe: int
    desc_informe: str
    cod_plataforma: int
    desc_plataforma: str

    class Config:
        from_attributes = True

class Auditoria_AccesoCreate(BaseModel):
    desc_auditoria_acceso: str
    fecha: datetime
    cod_usuario: int
    #run_usuario: str
    cod_informe: int
    cod_plataforma: int
    desc_plataforma: str
    
    class Config:
        from_attributes = True


class Auditoria_AccesoUpdate(BaseModel):
    desc_auditoria_acceso: str
    fecha: datetime
    cod_usuario: int
    #run_usuario: str
    cod_informe: int

    class Config:
        from_attributes = True