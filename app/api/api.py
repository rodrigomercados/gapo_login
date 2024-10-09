from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session,joinedload
from app.api.dependencies import get_db
from app.db.models import Tipo_Usuario,Usuario,UsuarioInforme,Informe,AuditoriaAcceso,Plataforma, EjecutivoPlataforma, Cliente
from app.core.security import create_access_token
from app.schemas.token import Token, TokenData,UrlInfo
from app.schemas.usuario import UsuarioCreate, UsuarioUpdate, UsuarioResponse
from app.schemas.tipo_usuario import Tipo_UsuarioCreate, Tipo_UsuarioUpdate, Tipo_UsuarioResponse
from app.schemas.auditoria_acceso import Auditoria_AccesoCreate,Auditoria_AccesoResponse,Auditoria_AccesoUpdate
from app.schemas.ejecutivo_plataforma import EjecutivoPlataformaCreate, EjecutivoPlataformaResponse
from app.schemas.plataforma import PlataformaCreate, PlataformaResponse, PlataformaUpdate
from app.schemas.cliente import ClienteCreate, ClienteResponse, ClienteUpdate

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
    
    # Obtener la lista de URLs de informes relacionados
    usuario_informes = db.query(UsuarioInforme).filter(UsuarioInforme.cod_usuario == user.cod_usuario).all()
    #urls = [db.query(Informe).filter(Informe.cod_informe == ui.cod_informe).first().url for ui in usuario_informes]


    # Obtener la plataforma asociada con el usuario
    ejecutivo_plataforma = db.query(EjecutivoPlataforma).filter(
        EjecutivoPlataforma.cod_usuario == user.cod_usuario,
        EjecutivoPlataforma.activo == True
    ).first()

    cod_plataforma = None
    desc_plataforma = None

    if ejecutivo_plataforma:
        plataforma = db.query(Plataforma).filter(
            Plataforma.cod_plataforma == ejecutivo_plataforma.cod_plataforma
        ).first()
        if plataforma:
            cod_plataforma = plataforma.cod_plataforma
            desc_plataforma = plataforma.desc_plataforma



    # Obtener la lista de URLs de informes relacionados con el usuario
    usuario_informes = db.query(UsuarioInforme).filter(UsuarioInforme.cod_usuario == user.cod_usuario).all()
    urls_usuario = [
        UrlInfo(
            cod_informe=ui.cod_informe,
            desc_informe=db.query(Informe).filter(Informe.cod_informe == ui.cod_informe).first().desc_informe,
            cod_tipo_usuario=user.cod_tipo_usuario,
            url=db.query(Informe).filter(Informe.cod_informe == ui.cod_informe).first().url
        )
        for ui in usuario_informes
    ]

    # Obtener la lista de informes de los usuarios que tienen como superior al usuario autenticado
    subordinados = db.query(Usuario).filter(Usuario.cod_superior == user.cod_usuario).all()
    urls_subordinados = []
    for sub in subordinados:
        sub_informes = db.query(UsuarioInforme).filter(UsuarioInforme.cod_usuario == sub.cod_usuario).all()
        for si in sub_informes:
            informe = db.query(Informe).filter(Informe.cod_informe == si.cod_informe).first()
            if informe:
                urls_subordinados.append(
                    UrlInfo(
                        cod_informe=informe.cod_informe,
                        desc_informe=informe.desc_informe,
                        cod_tipo_usuario=sub.cod_tipo_usuario,
                        url=informe.url
                    )
                )

    # Combinar ambas listas y eliminar duplicados
    all_urls = { (url.cod_informe, url.desc_informe, url.url): url for url in (urls_usuario + urls_subordinados) }
    combined_urls = list(all_urls.values())

    access_token = create_access_token(data={"sub": user.username})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "cod_usuario": user.cod_usuario,
        "desc_usuario": user.desc_usuario,
        "cod_tipo_usuario": user.cod_tipo_usuario,
        "cod_plataforma": cod_plataforma if cod_plataforma is not None else -1,
        "desc_plataforma": desc_plataforma if desc_plataforma is not None else "",
        "urls_usuario": combined_urls#urls
    }


############################################
###########    Usuarios    #################
############################################

@router.post("/usuarios/", response_model=UsuarioCreate, status_code=status.HTTP_201_CREATED, tags=["Usuarios"], operation_id="post_usuario")
def create_usuario(user: UsuarioCreate, db: Session = Depends(get_db), user_token: str = Depends(get_current_user)):
    #if not user_token:
    #    raise HTTPException(status_code=400, detail="Usuario Inactivo")
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


############################################
###########    Post Auditoría   ############
############################################
    
@router.post("/auditoria_acceso/", response_model=Auditoria_AccesoCreate, status_code=status.HTTP_201_CREATED, tags=["Auditoría Acceso"], operation_id="post_auditoria_acceso")
def create_auditoria_acceso(auditoria_acceso: Auditoria_AccesoCreate, db: Session = Depends(get_db), user_token: str = Depends(get_current_user)):
    if not user_token:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    #db_tipo_usuario = db.query(Tipo_Usuario).filter(Tipo_Usuario.desc_tipo_usuario == tipo_usuario.desc_tipo_usuario).first()
    db_auditoria_acceso = db.query(AuditoriaAcceso).filter(AuditoriaAcceso.desc_auditoria_acceso == auditoria_acceso.desc_auditoria_acceso).first()
    if db_auditoria_acceso:
        raise HTTPException(status_code=400, detail="Auditoria ya registrada")
    db_auditoria_acceso = AuditoriaAcceso(
        desc_auditoria_acceso=auditoria_acceso.desc_auditoria_acceso,
        fecha=auditoria_acceso.fecha,
        cod_usuario = auditoria_acceso.cod_usuario,
        #run_usuario = auditoria_acceso.run_usuario,
        cod_informe = auditoria_acceso.cod_informe,
        cod_plataforma = auditoria_acceso.cod_plataforma,
        desc_plataforma = auditoria_acceso.desc_plataforma
    )
    db.add(db_auditoria_acceso)
    db.commit()
    #db.refresh(db_auditoria_acceso)
    return db_auditoria_acceso

@router.get("/auditoria_acceso/", response_model=List[Auditoria_AccesoResponse], tags=["Auditoría Acceso"], operation_id="get_auditoria_acceso")
def read_auditoria_acceso(db: Session = Depends(get_db), user_token: str = Depends(get_current_user)):
    if not user_token:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    auditoria_acceso = db.query(AuditoriaAcceso).options(
        joinedload(AuditoriaAcceso.usuario),
        joinedload(AuditoriaAcceso.informe)
    ).filter(
        AuditoriaAcceso.cod_usuario != None,
        AuditoriaAcceso.cod_informe != None
    ).all()
    
    if not auditoria_acceso:
        raise HTTPException(status_code=404, detail="Auditoria Acceso no encontrada")
    
    response = []
    for audit in auditoria_acceso:
        response.append({
            "cod_auditoria_acceso": audit.cod_auditoria_acceso,
            "desc_auditoria_acceso": audit.desc_auditoria_acceso,
            "fecha": audit.fecha,
            "cod_usuario": audit.cod_usuario,
            "run_usuario": audit.usuario.run_usuario if audit.usuario else None,
            "nombres_usuario": audit.usuario.nombres_usuario if audit.usuario else None,
            "apellido_paterno_usuario": audit.usuario.apellido_paterno_usuario if audit.usuario else None,
            "apellido_materno_usuario": audit.usuario.apellido_materno_usuario if audit.usuario else None,
            "cod_informe": audit.cod_informe,
            "desc_informe": audit.informe.desc_informe if audit.informe else None,
            "cod_plataforma":audit.cod_plataforma if audit.cod_plataforma is not None else -1,
            "desc_plataforma":audit.desc_plataforma if audit.desc_plataforma is not None else "Sin Información"
        })
    return response

############################################
###########       Clientes       ###########
############################################

@router.post("/clientes/", response_model=ClienteResponse, status_code=status.HTTP_201_CREATED, tags=["Clientes"], operation_id="post_cliente")
def create_cliente(cliente: ClienteCreate, db: Session = Depends(get_db), user_token: str = Depends(get_current_user)):
    if not user_token:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    db_cliente = Cliente(**cliente.dict())
    db.add(db_cliente)
    db.commit()
    db.refresh(db_cliente)
    return db_cliente

@router.put("/clientes/{cod_cliente}", response_model=ClienteResponse, tags=["Clientes"], operation_id="put_cliente")
def update_cliente(cod_cliente: int, cliente: ClienteUpdate, db: Session = Depends(get_db), user_token: str = Depends(get_current_user)):
    if not user_token:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    db_cliente = db.query(Cliente).filter(Cliente.cod_cliente == cod_cliente).first()
    if not db_cliente:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")
    for key, value in cliente.dict(exclude_unset=True).items():
        setattr(db_cliente, key, value)
    db.commit()
    db.refresh(db_cliente)
    return db_cliente

@router.get("/clientes/", response_model=List[ClienteResponse], tags=["Clientes"], operation_id="get_clientes")
def read_clientes(db: Session = Depends(get_db), user_token: str = Depends(get_current_user)):
    if not user_token:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    clientes = db.query(Cliente).all()
    if not clientes:
        raise HTTPException(status_code=404, detail="Clientes no encontrados")
    return clientes

@router.get("/clientes/{cod_cliente}", response_model=ClienteResponse, tags=["Clientes"], operation_id="get_cliente_con_codigo")
def read_cliente(cod_cliente: int, db: Session = Depends(get_db), user_token: str = Depends(get_current_user)):
    if not user_token:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    cliente = db.query(Cliente).filter(Cliente.cod_cliente == cod_cliente).first()
    if not cliente:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")
    return cliente

@router.delete("/clientes/{cod_cliente}", response_model=ClienteResponse, tags=["Clientes"], operation_id="delete_cliente")
def delete_cliente(cod_cliente: int, db: Session = Depends(get_db), user_token: str = Depends(get_current_user)):
    if not user_token:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    db_cliente = db.query(Cliente).filter(Cliente.cod_cliente == cod_cliente).first()
    if not db_cliente:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")
    db.delete(db_cliente)
    db.commit()
    return db_cliente


############################################
###########    Plataformas     #############
############################################

from app.schemas.plataforma import PlataformaCreate, PlataformaUpdate, PlataformaResponse
from app.db.models import Plataforma

@router.post("/plataformas/", response_model=PlataformaResponse, status_code=status.HTTP_201_CREATED, tags=["Plataformas"], operation_id="post_plataforma")
def create_plataforma(plataforma: PlataformaCreate, db: Session = Depends(get_db), user_token: str = Depends(get_current_user)):
    if not user_token:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    db_plataforma = Plataforma(**plataforma.dict())
    db.add(db_plataforma)
    db.commit()
    db.refresh(db_plataforma)
    return db_plataforma

@router.put("/plataformas/{cod_plataforma}", response_model=PlataformaResponse, tags=["Plataformas"], operation_id="put_plataforma")
def update_plataforma(cod_plataforma: int, plataforma: PlataformaUpdate, db: Session = Depends(get_db), user_token: str = Depends(get_current_user)):
    if not user_token:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    db_plataforma = db.query(Plataforma).filter(Plataforma.cod_plataforma == cod_plataforma).first()
    if not db_plataforma:
        raise HTTPException(status_code=404, detail="Plataforma no encontrada")
    for key, value in plataforma.dict(exclude_unset=True).items():
        setattr(db_plataforma, key, value)
    db.commit()
    db.refresh(db_plataforma)
    return db_plataforma

@router.get("/plataformas/", response_model=List[PlataformaResponse], tags=["Plataformas"], operation_id="get_plataformas")
def read_plataformas(db: Session = Depends(get_db), user_token: str = Depends(get_current_user)):
    if not user_token:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    plataformas = db.query(Plataforma).all()
    if not plataformas:
        raise HTTPException(status_code=404, detail="Plataformas no encontradas")
    return plataformas

@router.get("/plataformas/{cod_plataforma}", response_model=PlataformaResponse, tags=["Plataformas"], operation_id="get_plataforma_con_codigo")
def read_plataforma(cod_plataforma: int, db: Session = Depends(get_db), user_token: str = Depends(get_current_user)):
    if not user_token:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    plataforma = db.query(Plataforma).filter(Plataforma.cod_plataforma == cod_plataforma).first()
    if not plataforma:
        raise HTTPException(status_code=404, detail="Plataforma no encontrada")
    return plataforma

@router.delete("/plataformas/{cod_plataforma}", response_model=PlataformaResponse, tags=["Plataformas"], operation_id="delete_plataforma")
def delete_plataforma(cod_plataforma: int, db: Session = Depends(get_db), user_token: str = Depends(get_current_user)):
    if not user_token:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    db_plataforma = db.query(Plataforma).filter(Plataforma.cod_plataforma == cod_plataforma).first()
    if not db_plataforma:
        raise HTTPException(status_code=404, detail="Plataforma no encontrada")
    db.delete(db_plataforma)
    db.commit()
    return db_plataforma


############################################
########### EjecutivoPlataforma ###########
############################################

from app.schemas.ejecutivo_plataforma import EjecutivoPlataformaCreate, EjecutivoPlataformaUpdate, EjecutivoPlataformaResponse
from app.db.models import EjecutivoPlataforma

@router.post("/ejecutivos_plataforma/", response_model=EjecutivoPlataformaResponse, status_code=status.HTTP_201_CREATED, tags=["EjecutivosPlataforma"], operation_id="post_ejecutivo_plataforma")
def create_ejecutivo_plataforma(ejecutivo_plataforma: EjecutivoPlataformaCreate, db: Session = Depends(get_db), user_token: str = Depends(get_current_user)):
    if not user_token:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    db_ejecutivo_plataforma = EjecutivoPlataforma(**ejecutivo_plataforma.dict())
    db.add(db_ejecutivo_plataforma)
    db.commit()
    db.refresh(db_ejecutivo_plataforma)
    return db_ejecutivo_plataforma

@router.put("/ejecutivos_plataforma/{cod_ejecutivo_plataforma}", response_model=EjecutivoPlataformaResponse, tags=["EjecutivosPlataforma"], operation_id="put_ejecutivo_plataforma")
def update_ejecutivo_plataforma(cod_ejecutivo_plataforma: int, ejecutivo_plataforma: EjecutivoPlataformaUpdate, db: Session = Depends(get_db), user_token: str = Depends(get_current_user)):
    if not user_token:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    db_ejecutivo_plataforma = db.query(EjecutivoPlataforma).filter(EjecutivoPlataforma.cod_ejecutivo_plataforma == cod_ejecutivo_plataforma).first()
    if not db_ejecutivo_plataforma:
        raise HTTPException(status_code=404, detail="EjecutivoPlataforma no encontrado")
    for key, value in ejecutivo_plataforma.dict(exclude_unset=True).items():
        setattr(db_ejecutivo_plataforma, key, value)
    db.commit()
    db.refresh(db_ejecutivo_plataforma)
    return db_ejecutivo_plataforma

@router.get("/ejecutivos_plataforma/", response_model=List[EjecutivoPlataformaResponse], tags=["EjecutivosPlataforma"], operation_id="get_ejecutivos_plataforma")
def read_ejecutivos_plataforma(db: Session = Depends(get_db), user_token: str = Depends(get_current_user)):
    if not user_token:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    ejecutivos_plataforma = db.query(EjecutivoPlataforma).all()
    if not ejecutivos_plataforma:
        raise HTTPException(status_code=404, detail="EjecutivosPlataforma no encontrados")
    return ejecutivos_plataforma

@router.get("/ejecutivos_plataforma/{cod_ejecutivo_plataforma}", response_model=EjecutivoPlataformaResponse, tags=["EjecutivosPlataforma"], operation_id="get_ejecutivo_plataforma_con_codigo")
def read_ejecutivo_plataforma(cod_ejecutivo_plataforma: int, db: Session = Depends(get_db), user_token: str = Depends(get_current_user)):
    if not user_token:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    ejecutivo_plataforma = db.query(EjecutivoPlataforma).filter(EjecutivoPlataforma.cod_ejecutivo_plataforma == cod_ejecutivo_plataforma).first()
    if not ejecutivo_plataforma:
        raise HTTPException(status_code=404, detail="EjecutivoPlataforma no encontrado")
    return ejecutivo_plataforma

@router.delete("/ejecutivos_plataforma/{cod_ejecutivo_plataforma}", response_model=EjecutivoPlataformaResponse, tags=["EjecutivosPlataforma"], operation_id="delete_ejecutivo_plataforma")
def delete_ejecutivo_plataforma(cod_ejecutivo_plataforma: int, db: Session = Depends(get_db), user_token: str = Depends(get_current_user)):
    if not user_token:
        raise HTTPException(status_code=400, detail="Usuario Inactivo")
    db_ejecutivo_plataforma = db.query(EjecutivoPlataforma).filter(EjecutivoPlataforma.cod_ejecutivo_plataforma == cod_ejecutivo_plataforma).first()
    if not db_ejecutivo_plataforma:
        raise HTTPException(status_code=404, detail="EjecutivoPlataforma no encontrado")
    db.delete(db_ejecutivo_plataforma)
    db.commit()
    return db_ejecutivo_plataforma
