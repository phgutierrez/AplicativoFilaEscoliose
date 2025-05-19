from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, Float, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base


class Usuario(Base):
    __tablename__ = 'usuarios'

    id = Column(Integer, primary_key=True)
    usuario = Column(String(50), unique=True, nullable=False)
    senha = Column(String(255), nullable=False)
    perfil = Column(String(20), nullable=False)
    senha_temporaria = Column(Boolean, default=True)

    def __repr__(self):
        return f'<Usuario {self.usuario}>'


class Paciente(Base):
    __tablename__ = 'pacientes'

    id = Column(Integer, primary_key=True)
    nome = Column(String(255), nullable=False)
    nascimento = Column(String(10), nullable=False)
    contato = Column(String(50))
    municipio = Column(String(100))
    medico_assistente = Column(String(100))
    versao = Column(Integer, default=1)

    consultas = relationship(
        "Consulta", back_populates="paciente", cascade="all, delete-orphan")
    agendamentos = relationship(
        "Agendamento", back_populates="paciente", cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Paciente {self.nome}>'


class Consulta(Base):
    __tablename__ = 'consultas'

    id = Column(Integer, primary_key=True)
    paciente_id = Column(Integer, ForeignKey('pacientes.id'), nullable=False)
    data = Column(String(10), nullable=False)
    escore = Column(Integer, nullable=False)
    prioridade = Column(String(50), nullable=False)
    escore_anterior = Column(Integer)
    prioridade_anterior = Column(String(50))
    is_demanda_judicial = Column(Boolean, default=False)
    data_judicial = Column(String(50))
    tipo_escoliose = Column(String(50))
    grau_curva = Column(String(50))
    observacoes = Column(String(1000))
    versao = Column(Integer, default=1)

    paciente = relationship("Paciente", back_populates="consultas")

    def __repr__(self):
        return f'<Consulta {self.id} de {self.paciente_id}>'


class Operado(Base):
    __tablename__ = 'operados'

    id = Column(Integer, primary_key=True)
    nome = Column(String(255), nullable=False)
    nascimento = Column(String(10), nullable=False)
    data_consulta = Column(String(10), nullable=False)
    escore = Column(Integer, nullable=False)
    prioridade = Column(String(50), nullable=False)
    data_realizacao = Column(String(10), nullable=False)

    def __repr__(self):
        return f'<Operado {self.nome}>'


class Agendamento(Base):
    __tablename__ = 'agendamentos'

    id = Column(Integer, primary_key=True)
    paciente_id = Column(Integer, ForeignKey('pacientes.id'), nullable=False)
    data_cirurgia = Column(String(10), nullable=False)
    realizado = Column(Boolean, default=False)

    paciente = relationship("Paciente", back_populates="agendamentos")

    def __repr__(self):
        return f'<Agendamento {self.id} para {self.paciente_id}>'
