from sqlalchemy import Column, Integer, String, BigInteger, ForeignKey, TIMESTAMP, create_engine, Date, SmallInteger, DateTime, Boolean
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


class Cliente(Base):
    __tablename__ = 'cliente'
    cod_cliente = Column(BigInteger, primary_key=True, autoincrement=True)
    rut_cliente = Column(String(12))
    razon_social = Column(String(255))
    telefono1 = Column(String(12))
    telefono2 = Column(String(12))
    email = Column(String(100))
    desc_cliente = Column(String(255), nullable=False)
    direccion = Column(String(255))
    cod_comuna = Column(BigInteger, nullable=True)
    insertby = Column(String(100), nullable=False, default=func.current_user())
    inserttime = Column(Date, nullable=False, default=func.now())

    plataformas = relationship("Plataforma", back_populates="cliente")

class Informe(Base):
    __tablename__ = 'informe'
    cod_informe = Column(BigInteger, primary_key=True, index=True)
    desc_informe = Column(String, nullable=False)
    url = Column(String)
    insertby = Column(String, nullable=False, default="CURRENT_USER")
    inserttime = Column(Date, nullable=False, default="now()")
    usuario_informe = relationship('UsuarioInforme', back_populates='informe')
    auditorias_acceso = relationship('AuditoriaAcceso', back_populates='informe')

class UsuarioInforme(Base):
    __tablename__ = 'usuario_informe'
    cod_usuario_informe = Column(BigInteger, primary_key=True, index=True)
    desc_usuario_informe = Column(String, nullable=False)
    cod_usuario = Column(BigInteger, ForeignKey('usuario.cod_usuario'))
    cod_informe = Column(BigInteger, ForeignKey('informe.cod_informe'))
    insertby = Column(String, nullable=False, default="CURRENT_USER")
    inserttime = Column(Date, nullable=False, default="now()")
    usuario = relationship('Usuario', back_populates='informes_usuario_informe')
    informe = relationship('Informe', back_populates='usuario_informe')

class AuditoriaAcceso(Base):
    __tablename__ = 'auditoria_acceso'
    cod_auditoria_acceso = Column(BigInteger, primary_key=True, index=True)
    desc_auditoria_acceso = Column(String, nullable=False)
    fecha = Column(DateTime, nullable=False, default=func.now())
    cod_usuario = Column(BigInteger, ForeignKey('usuario.cod_usuario'))
    #run_usuario = Column(BigInteger)
    cod_informe = Column(BigInteger, ForeignKey('informe.cod_informe'))
    cod_plataforma = Column(BigInteger, nullable=False)
    desc_plataforma = Column(String, nullable=False)
    insertby = Column(String, nullable=False, default="CURRENT_USER")
    inserttime = Column(DateTime, nullable=False, default=func.now())
    usuario = relationship('Usuario', back_populates='auditorias_acceso')
    informe = relationship('Informe', back_populates='auditorias_acceso')




# Modelo Plataforma
class Plataforma(Base):
    __tablename__ = "plataforma"

    cod_plataforma = Column(BigInteger, primary_key=True, index=True)
    desc_plataforma = Column(String, nullable=False)
    insertby = Column(String, nullable=False, default="CURRENT_USER")
    inserttime = Column(Date, nullable=False, default="now()")
    cod_cliente = Column(BigInteger, ForeignKey("cliente.cod_cliente"), nullable=False)

    # Relación con EjecutivoPlataforma
    ejecutivos = relationship("EjecutivoPlataforma", back_populates="plataforma")
    cliente = relationship("Cliente", back_populates="plataformas")

    # Modelo EjecutivoPlataforma
class EjecutivoPlataforma(Base):
    __tablename__ = "ejecutivo_plataforma"

    cod_ejecutivo_plataforma = Column(BigInteger, primary_key=True, index=True)
    desc_ejecutivo_plataforma = Column(String, nullable=False)
    insertby = Column(String, nullable=False, default="CURRENT_USER")
    inserttime = Column(Date, nullable=False, default="now()")
    cod_usuario = Column(BigInteger, ForeignKey("usuario.cod_usuario"), nullable=True)
    cod_plataforma = Column(BigInteger, ForeignKey("plataforma.cod_plataforma"), nullable=True)
    activo = Column(Boolean, nullable=True)

    usuario = relationship("Usuario", back_populates="plataformas")
    plataforma = relationship("Plataforma", back_populates="ejecutivos")


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
    mail = Column(String)
    insertby = Column(String, default=func.current_user())
    inserttime = Column(TIMESTAMP, default=func.now())
    cod_tipo_usuario = Column(BigInteger, ForeignKey('tipo_usuario.cod_tipo_usuario'), nullable=False)
    cod_superior = Column(BigInteger, ForeignKey('usuario.cod_usuario'), nullable=True)

    informes_usuario_informe = relationship('UsuarioInforme', back_populates='usuario')
    auditorias_acceso = relationship('AuditoriaAcceso', back_populates='usuario')
    tipo_usuario = relationship("Tipo_Usuario")
    plataformas = relationship("EjecutivoPlataforma", back_populates="usuario")

    def verify_password(self, plain_password):
        return pwd_context.verify(plain_password, self.contrasena)

