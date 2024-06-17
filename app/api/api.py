from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app.api.dependencies import get_db
from app.db.models import Usuario, Tipo_Usuario  # Modelos de SQLAlchemy
from app.db.models import Tipo_Usuario
from app.core.security import create_access_token
from app.schemas.token import Token, TokenData
from app.schemas.usuario import UsuarioCreate, UsuarioUpdate, UsuarioResponse
from app.schemas.tipo_usuario import Tipo_UsuarioCreate, Tipo_UsuarioUpdate, Tipo_UsuarioResponse
from passlib.context import CryptContext
from typing import List, Optional, Annotated, Dict
from ..core.config import Settings
from ..core.security import ALGORITHM
from jose import jwt, JWTError










router = APIRouter()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

def get_user(db: Session, username: str):
    return db.query(Usuario).filter(Usuario.username == username).first()

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, Settings.SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
        user = get_user(db, username)
        if user is None:
            raise credentials_exception
        return user    
    except JWTError:
        raise credentials_exception

async def get_current_active_user(
    current_user: Annotated[Usuario, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    return current_user

@router.post("/token", response_model=Token, tags=["Z Token"])
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(Usuario).filter(Usuario.username == form_data.username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Usuario incorrecto")
    if not user.verify_password(form_data.password):
        raise HTTPException(status_code=401, detail="Password incorrecta")
    access_token = create_access_token(data={"sub": user.username})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "desc_usuario": user.desc_usuario,
        "cod_tipo_usuario": user.cod_tipo_usuario
    }


############################################
###########    Usuarios    #################
############################################

@router.post("/usuarios/", response_model=UsuarioCreate, status_code=status.HTTP_201_CREATED, tags=["Usuarios"], operation_id="post_usuario")
def create_usuario(user: UsuarioCreate, db: Session = Depends(get_db), user_token: str = Depends(get_current_user)):
    if not user_token:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    db_user = db.query(Usuario).filter(Usuario.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = hash_password(user.contrasena)
    db_user = Usuario(
        run_usuario=user.run_usuario,
        nombres_usuario=user.nombres_usuario,
        apellido_paterno_usuario=user.apellido_paterno_usuario,
        apellido_materno_usuario=user.apellido_materno_usuario,
        direccion_usuario=user.direccion_usuario,
        telefono=user.telefono,
        mail=user.mail,
        username=user.username,
        contrasena=hashed_password,
        desc_usuario=user.desc_usuario,
        cod_tipo_usuario=user.cod_tipo_usuario,
        cod_superior=user.cod_superior
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@router.put("/usuarios/{cod_usuario}", response_model=UsuarioUpdate, tags=["Usuarios"], operation_id="put_usuario")
def update_usuario(
    cod_usuario: int, 
    usuario: UsuarioUpdate, 
    db: Session = Depends(get_db), 
    current_user: Usuario = Depends(get_current_user)
):
    if not current_user:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    db_usuario = db.query(Usuario).filter(Usuario.cod_usuario == cod_usuario).first()
    if not db_usuario:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    for key, value in usuario.dict(exclude_unset=True).items():
        setattr(db_usuario, key, value)
    db.commit()
    db.refresh(db_usuario)
    return db_usuario

@router.get("/usuarios/", response_model=List[UsuarioResponse], tags=["Usuarios"], operation_id="get_usuario")
def read_usuarios(db: Session = Depends(get_db), user_token: str = Depends(get_current_user)):    
    if not user_token:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    usuarios = (
        db.query(Usuario)
        .join(Tipo_Usuario, Usuario.cod_tipo_usuario == Tipo_Usuario.cod_tipo_usuario)
        .all()
    )
    if not usuarios:
        raise HTTPException(status_code=404, detail="Usuarios no encontrados")

    usuarios_response = [
        UsuarioResponse(
            cod_usuario=usuario.cod_usuario,
            run_usuario=usuario.run_usuario,
            nombres_usuario=usuario.nombres_usuario,
            apellido_paterno_usuario=usuario.apellido_paterno_usuario,
            apellido_materno_usuario=usuario.apellido_materno_usuario,
            direccion_usuario=usuario.direccion_usuario,
            telefono=usuario.telefono,
            email=usuario.mail,  # Asegúrate de que el campo email esté presente
            username=usuario.username,
            #contrasena=usuario.contrasena,  # No deberías devolver la contraseña en la respuesta
            desc_usuario=usuario.desc_usuario,
            desc_tipo_usuario=usuario.tipo_usuario.desc_tipo_usuario
        ) for usuario in usuarios
    ]
    return usuarios_response

@router.get("/usuarios/{cod_usuario}", response_model=List[UsuarioResponse], tags=["Usuarios"], operation_id="get_usuario_con_codigo")
def read_usuario(cod_usuario: int, db: Session = Depends(get_db), user_token: str = Depends(get_current_user)):
    if not user_token:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    usuario = (
        db.query(Usuario)
        .filter(Usuario.cod_usuario == cod_usuario)
        .join(Tipo_Usuario, Usuario.cod_tipo_usuario == Tipo_Usuario.cod_tipo_usuario)
        .first()
    )
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    usuario_response = UsuarioResponse(
        cod_usuario=usuario.cod_usuario,
        run_usuario=usuario.run_usuario,
        nombres_usuario=usuario.nombres_usuario,
        apellido_paterno_usuario=usuario.apellido_paterno_usuario,
        apellido_materno_usuario=usuario.apellido_materno_usuario,
        direccion_usuario=usuario.direccion_usuario,
        telefono=usuario.telefono,
        email=usuario.mail,
        username=usuario.username,
        #contrasena=hash_password(usuario.contrasena),
        desc_usuario=usuario.desc_usuario,
        desc_tipo_usuario=usuario.tipo_usuario.desc_tipo_usuario
    ) 
    return [usuario_response]

@router.delete("/usuarios/{cod_usuario}", response_model=UsuarioResponse, tags=["Usuarios"], operation_id="delete_usuario")
def delete_usuario(cod_usuario: int, db: Session = Depends(get_db), current_user: Usuario = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    db_usuario = db.query(Usuario).filter(Usuario.cod_usuario == cod_usuario).first()
    if not db_usuario:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    db.delete(db_usuario)
    db.commit()
    return db_usuario


############################################
###########    Tipo Usuarios    ############
############################################

@router.post("/tipo_usuarios/", response_model=Tipo_UsuarioResponse, status_code=status.HTTP_201_CREATED, tags=["Tipo Usuarios"], operation_id="post_tipo_usuario")
def create_tipo_usuario(tipo_usuario: Tipo_UsuarioCreate, db: Session = Depends(get_db), user_token: str = Depends(get_current_user)):
    if not user_token:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    db_tipo_usuario = db.query(Tipo_Usuario).filter(Tipo_Usuario.desc_tipo_usuario == tipo_usuario.desc_tipo_usuario).first()
    if db_tipo_usuario:
        raise HTTPException(status_code=400, detail="Tipo de Usuario ya registrado")
    db_tipo_usuario = Tipo_Usuario(
        desc_tipo_usuario=tipo_usuario.desc_tipo_usuario
    )
    db.add(db_tipo_usuario)
    db.commit()
    db.refresh(db_tipo_usuario)
    return db_tipo_usuario

@router.put("/tipo_usuarios/{cod_tipo_usuario}", response_model=Tipo_UsuarioUpdate, tags=["Tipo Usuarios"], operation_id="put_tipo_usuario")
def update_tipo_usuario(
    cod_tipo_usuario: int, 
    tipo_usuario: Tipo_UsuarioUpdate, 
    db: Session = Depends(get_db), 
    current_user: Usuario = Depends(get_current_user)
):
    if not current_user:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    db_tipo_usuario = db.query(Tipo_Usuario).filter(Tipo_Usuario.cod_tipo_usuario == cod_tipo_usuario).first()
    if not db_tipo_usuario:
        raise HTTPException(status_code=404, detail="Tipo de Usuario no encontrado")
    for key, value in tipo_usuario.dict(exclude_unset=True).items():
        setattr(db_tipo_usuario, key, value)
    db.commit()
    db.refresh(db_tipo_usuario)
    return db_tipo_usuario

@router.get("/tipo_usuarios/", response_model=List[Tipo_UsuarioResponse], tags=["Tipo Usuarios"], operation_id="get_tipo_usuarios")
def read_tipo_usuarios(db: Session = Depends(get_db), user_token: str = Depends(get_current_user)):
    if not user_token:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    tipo_usuarios = db.query(Tipo_Usuario).all()
    if not tipo_usuarios:
        raise HTTPException(status_code=404, detail="Tipos de Usuario no encontrados")
    return tipo_usuarios

@router.get("/tipo_usuarios/{cod_tipo_usuario}", response_model=Tipo_UsuarioResponse, tags=["Tipo Usuarios"], operation_id="get_tipo_usuario_con_codigo")
def read_tipo_usuario(cod_tipo_usuario: int, db: Session = Depends(get_db), user_token: str = Depends(get_current_user)):
    if not user_token:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    tipo_usuario = db.query(Tipo_Usuario).filter(Tipo_Usuario.cod_tipo_usuario == cod_tipo_usuario).first()
    if not tipo_usuario:
        raise HTTPException(status_code=404, detail="Tipo de Usuario no encontrado")
    return tipo_usuario

@router.delete("/tipo_usuarios/{cod_tipo_usuario}", response_model=Tipo_UsuarioResponse, tags=["Tipo Usuarios"], operation_id="delete_tipo_usuario")
def delete_tipo_usuario(cod_tipo_usuario: int, db: Session = Depends(get_db), current_user: Usuario = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    db_tipo_usuario = db.query(Tipo_Usuario).filter(Tipo_Usuario.cod_tipo_usuario == cod_tipo_usuario).first()
    if not db_tipo_usuario:
        raise HTTPException(status_code=404, detail="Tipo de Usuario no encontrado")
    db.delete(db_tipo_usuario)
    db.commit()
    return db_tipo_usuario

    