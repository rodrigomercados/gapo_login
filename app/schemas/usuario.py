# User schemas
# app/schemas/user.py
from pydantic import BaseModel, EmailStr
from typing import Optional

class Usuario(BaseModel):
    username: str

class UsuarioResponse(BaseModel):
    cod_usuario: int
    run_usuario: str
    nombres_usuario: str
    apellido_paterno_usuario: str
    apellido_materno_usuario: str
    direccion_usuario: str
    telefono: Optional[str] = None
    email: EmailStr  # Asegúrate de que este campo sea requerido
    username: str
    #contrasena: str  # Considera no devolver este campo en la respuesta
    desc_usuario: str
    desc_tipo_usuario: str
    #cod_superior:int

    class Config:
        from_attributes = True

class UsuarioCreate(BaseModel):
    run_usuario: str
    nombres_usuario: str
    apellido_paterno_usuario: str
    apellido_materno_usuario: str
    direccion_usuario: str
    telefono: str
    mail: EmailStr
    username: str
    contrasena: str
    desc_usuario: str
    cod_tipo_usuario: int
    cod_superior: int

    class Config:
        #orm_mode = True
        #from_orm = True
        from_attributes = True

class UsuarioUpdate(BaseModel):
    run_usuario: str | None = None
    nombres_usuario: str | None = None
    apellido_paterno_usuario: str | None = None
    apellido_materno_usuario: str | None = None
    direccion_usuario: str | None = None
    telefono: str | None = None
    mail: EmailStr | None = None
    username: str | None = None
    contrasena: str | None = None
    desc_usuario: str | None = None
    cod_tipo_usuario: int | None = None
    cod_superior: int | None = None

    class Config:
        #orm_mode = True
        #from_orm = True
        from_attributes = True
