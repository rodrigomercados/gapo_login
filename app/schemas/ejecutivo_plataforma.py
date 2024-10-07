from pydantic import BaseModel
from typing import Optional
from datetime import date

# Esquema de respuesta para EjecutivoPlataforma
class EjecutivoPlataformaResponse(BaseModel):
    cod_ejecutivo_plataforma: int
    desc_ejecutivo_plataforma: str
    cod_usuario: int
    cod_plataforma: int
    activo: Optional[bool] = None

    class Config:
        from_attributes = True


# Esquema para la creación de un EjecutivoPlataforma
class EjecutivoPlataformaCreate(BaseModel):
    desc_ejecutivo_plataforma: str
    cod_usuario: int
    cod_plataforma: int
    activo: Optional[bool] = None

    class Config:
        from_attributes = True


# Esquema para la actualización de un EjecutivoPlataforma
class EjecutivoPlataformaUpdate(BaseModel):
    desc_ejecutivo_plataforma: Optional[str] = None
    cod_usuario: Optional[int] = None
    cod_plataforma: Optional[int] = None
    activo: Optional[bool] = None

    class Config:
        from_attributes = True
