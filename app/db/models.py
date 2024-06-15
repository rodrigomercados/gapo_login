from sqlalchemy import Column, Integer, String, BigInteger, ForeignKey, TIMESTAMP, create_engine, Date, SmallInteger
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from passlib.context import CryptContext
from sqlalchemy.orm import relationship

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

Base = declarative_base()

class Tipo_Usuario(Base):
    __tablename__ = 'tipo_usuario'

    cod_tipo_usuario = Column(Integer, primary_key=True)
    desc_tipo_usuario = Column(String(255), nullable=False)
    insertby = Column(String(100), nullable=False, default=func.current_user())
    inserttime = Column(TIMESTAMP, nullable=False, default=func.now())

class Usuario(Base):
    __tablename__ = "usuario"
    cod_usuario = Column(Integer, primary_key=True, index=True)
    run_usuario = Column(String)
    username = Column(String, unique=True, index=True)
    contrasena = Column(String)
    desc_usuario = Column(String)
    nombres_usuario = Column(String)
    apellido_paterno_usuario = Column(String)
    apellido_materno_usuario = Column(String)
    direccion_usuario = Column(String)
    telefono = Column(String)
    mail = Column(String)  # Asegúrate de que este campo esté presente
    insertby = Column(String, default=func.current_user())
    inserttime = Column(TIMESTAMP, default=func.now())
    cod_tipo_usuario = Column(BigInteger, ForeignKey('tipo_usuario.cod_tipo_usuario'), nullable=False)
    cod_superior = Column(BigInteger,ForeignKey('usuario.cod_usuario'), nullable=True)

    tipo_usuario = relationship("Tipo_Usuario")
    
    def verify_password(self, plain_password):
        return pwd_context.verify(plain_password, self.contrasena)
