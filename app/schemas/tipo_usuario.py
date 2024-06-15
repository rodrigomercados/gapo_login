# schemas

from pydantic import BaseModel

class Tipo_UsuarioResponse(BaseModel):
    cod_tipo_usuario: int
    desc_tipo_usuario: str

    class Config:
        #from_orm = True
        #orm_mode = True
        from_attributes = True

class Tipo_UsuarioCreate(BaseModel):
    #cod_tipo_usuario: str
    desc_tipo_usuario: str

    class Config:
        #from_orm = True
        #orm_mode = True
        from_attributes = True

class Tipo_UsuarioUpdate(BaseModel):
    desc_tipo_usuario: str | None = None

    class Config:
        #orm_mode = True
        #from_orm = True
        from_attributes = True