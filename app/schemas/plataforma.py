from pydantic import BaseModel
from typing import Optional

# Esquema base para Plataforma
class PlataformaBase(BaseModel):
    cod_plataforma: int
    desc_plataforma: str

    class Config:
        from_attributes = True  # Permite que el esquema funcione con modelos de SQLAlchemy


# Esquema para la creación de una plataforma
class PlataformaCreate(BaseModel):
    desc_plataforma: str
    cod_cliente:int


# Esquema para la respuesta de una plataforma
class PlataformaResponse(PlataformaBase):
    cod_cliente: int | None = None

# Esquema para la actualización de una plataforma
class PlataformaUpdate(BaseModel):
    desc_plataforma: Optional[str] = None
    cod_cliente: Optional[int] = None

    class Config:
        from_attributes = True