from pydantic import BaseModel, EmailStr, Field
from typing import Optional

class ClienteBase(BaseModel):
    rut_cliente: Optional[str] = Field(max_length=12)
    razon_social: Optional[str] = Field(max_length=255)
    telefono1: Optional[str] = Field(max_length=12)
    telefono2: Optional[str] = Field(max_length=12)
    email: Optional[EmailStr]
    desc_cliente: str = Field(max_length=255)
    direccion: Optional[str] = Field(max_length=255)
    cod_comuna: Optional[int]

class ClienteCreate(ClienteBase):
    pass

class ClienteUpdate(ClienteBase):
    pass

class ClienteResponse(ClienteBase):
    cod_cliente: int
    insertby: str
    inserttime: Date

    class Config:
        from_attributes = True
