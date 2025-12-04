from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text, Boolean, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, scoped_session
from sqlalchemy.pool import QueuePool
from sqlalchemy.exc import SQLAlchemyError, IntegrityError, OperationalError
from datetime import datetime
from typing import Optional, Generator
from contextlib import contextmanager
import os

from utils.logger import get_logger
from utils.exceptions import DatabaseError, ValidationError
from core.config import Config

logger = get_logger(__name__)

Base = declarative_base()


class Agent(Base):
    __tablename__ = "agents"
    
    id = Column(String(36), primary_key=True)
    hostname = Column(String(255), nullable=False)
    ip = Column(String(45), nullable=False)
    os = Column(String(50), nullable=False)
    platform = Column(String(100))
    architecture = Column(String(20))
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    status = Column(String(20), default="active", nullable=False)
    public_key = Column(Text)
    version = Column(String(20))
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<Agent(id={self.id}, hostname={self.hostname}, ip={self.ip}, status={self.status})>"
    
    def to_dict(self):
        return {
            "id": self.id,
            "hostname": self.hostname,
            "ip": self.ip,
            "os": self.os,
            "platform": self.platform,
            "architecture": self.architecture,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "status": self.status,
            "version": self.version,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class Task(Base):
    __tablename__ = "tasks"
    
    id = Column(String(36), primary_key=True)
    agent_id = Column(String(36), ForeignKey("agents.id"), nullable=False)
    module_name = Column(String(100), nullable=False)
    payload = Column(JSON, nullable=False)
    status = Column(String(20), default="pending", nullable=False)
    priority = Column(String(10), default="normal")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    assigned_at = Column(DateTime)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    error = Column(Text)
    
    def __repr__(self):
        return f"<Task(id={self.id}, agent_id={self.agent_id}, module={self.module_name}, status={self.status})>"
    
    def to_dict(self):
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "module_name": self.module_name,
            "payload": self.payload,
            "status": self.status,
            "priority": self.priority,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "assigned_at": self.assigned_at.isoformat() if self.assigned_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error": self.error,
        }


class Result(Base):
    __tablename__ = "results"
    
    id = Column(String(36), primary_key=True)
    task_id = Column(String(36), ForeignKey("tasks.id"), nullable=False, unique=True)
    data = Column(JSON)
    output = Column(Text)
    error = Column(Text)
    exit_code = Column(Integer)
    execution_time = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f"<Result(id={self.id}, task_id={self.task_id}, exit_code={self.exit_code})>"
    
    def to_dict(self):
        return {
            "id": self.id,
            "task_id": self.task_id,
            "data": self.data,
            "output": self.output,
            "error": self.error,
            "exit_code": self.exit_code,
            "execution_time": self.execution_time,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Module(Base):
    __tablename__ = "modules"
    
    name = Column(String(100), primary_key=True)
    description = Column(Text)
    category = Column(String(50), nullable=False)
    parameters = Column(JSON)
    version = Column(String(20))
    author = Column(String(100))
    enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<Module(name={self.name}, category={self.category}, enabled={self.enabled})>"
    
    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "parameters": self.parameters,
            "version": self.version,
            "author": self.author,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class User(Base):
    __tablename__ = "users"
    
    id = Column(String(36), primary_key=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    email = Column(String(255))
    role = Column(String(20), default="user", nullable=False)
    active = Column(Boolean, default=True, nullable=False)
    last_login = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<User(id={self.id}, username={self.username}, role={self.role})>"
    
    def to_dict(self, include_sensitive=False):
        data = {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "active": self.active,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_sensitive:
            data["password_hash"] = self.password_hash
        return data


_engine: Optional[create_engine] = None
_session_factory: Optional[sessionmaker] = None
_scoped_session_factory: Optional[scoped_session] = None


def _get_database_url() -> str:
    Config.load()
    db_type = Config.get("DATABASE_TYPE") or "sqlite"
    db_type = db_type.lower()
    
    if db_type == "sqlite":
        db_path = Config.get("DATABASE_PATH") or "build/data/c2_framework.db"
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        logger.debug(f"[+] SQLite database path: {db_path}")
        return f"sqlite:///{db_path}"
    
    elif db_type == "postgresql":
        host = Config.get("DATABASE_HOST") or "localhost"
        port = Config.get("DATABASE_PORT") or "5432"
        name = Config.get("DATABASE_NAME") or "c2_framework"
        user = Config.get("DATABASE_USER")
        password = Config.get("DATABASE_PASSWORD")
        
        if not user or not password:
            logger.error("[-] PostgreSQL credentials missing")
            raise ValidationError("PostgreSQL requires DATABASE_USER and DATABASE_PASSWORD")
        
        logger.debug(f"[+] PostgreSQL connection: {user}@{host}:{port}/{name}")
        return f"postgresql://{user}:{password}@{host}:{port}/{name}"
    
    else:
        logger.error(f"[-] Unsupported database type: {db_type}")
        raise ValidationError(f"Unsupported database type: {db_type}")


def init_db() -> None:
    global _engine, _session_factory, _scoped_session_factory
    
    try:
        database_url = _get_database_url()
        logger.info(f"[+] Initializing database connection")
        
        Config.load()
        pool_size = int(Config.get("DATABASE_POOL_SIZE") or "10")
        max_overflow = int(Config.get("DATABASE_MAX_OVERFLOW") or "20")
        pool_timeout = int(Config.get("DATABASE_POOL_TIMEOUT") or "30")
        
        _engine = create_engine(
            database_url,
            poolclass=QueuePool,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_timeout=pool_timeout,
            pool_pre_ping=True,
            echo=False,
            connect_args={"check_same_thread": False} if "sqlite" in database_url else {}
        )
        
        _session_factory = sessionmaker(
            bind=_engine,
            autocommit=False,
            autoflush=False,
            expire_on_commit=False
        )
        
        _scoped_session_factory = scoped_session(_session_factory)
        
        logger.info("[+] Database connection initialized successfully")
        
    except ValidationError:
        raise
    except Exception as e:
        logger.error(f"[-] Database initialization failed: {e}", exc_info=True)
        raise DatabaseError(f"Database initialization failed: {str(e)}") from e


@contextmanager
def get_session() -> Generator[Session, None, None]:
    if _scoped_session_factory is None:
        logger.error("[-] Database not initialized")
        raise DatabaseError("Database not initialized. Call init_db() first.")
    
    session = _scoped_session_factory()
    
    try:
        yield session
        session.commit()
        logger.debug("[+] Database session committed")
    except IntegrityError as e:
        session.rollback()
        logger.warning(f"[!] Database integrity constraint violated: {e}")
        raise DatabaseError(f"Database integrity constraint violated: {str(e)}") from e
    except SQLAlchemyError as e:
        session.rollback()
        logger.error(f"[-] Database operation failed: {e}", exc_info=True)
        raise DatabaseError(f"Database operation failed: {str(e)}") from e
    except Exception as e:
        session.rollback()
        logger.error(f"[-] Unexpected database error: {e}", exc_info=True)
        raise DatabaseError(f"Unexpected database error: {str(e)}") from e
    finally:
        session.close()
        _scoped_session_factory.remove()


def create_tables() -> None:
    if _engine is None:
        logger.error("[-] Database not initialized")
        raise DatabaseError("Database not initialized. Call init_db() first.")
    
    try:
        logger.info("[+] Creating database tables")
        Base.metadata.create_all(_engine)
        logger.info("[+] Database tables created successfully")
    except Exception as e:
        logger.error(f"[-] Failed to create database tables: {e}", exc_info=True)
        raise DatabaseError(f"Failed to create database tables: {str(e)}") from e


def drop_tables() -> None:
    if _engine is None:
        logger.error("[-] Database not initialized")
        raise DatabaseError("Database not initialized. Call init_db() first.")
    
    try:
        logger.warning("[!] Dropping all database tables")
        Base.metadata.drop_all(_engine)
        logger.warning("[!] All database tables dropped")
    except Exception as e:
        logger.error(f"[-] Failed to drop database tables: {e}", exc_info=True)
        raise DatabaseError(f"Failed to drop database tables: {str(e)}") from e


def migrate_db() -> None:
    try:
        logger.info("[+] Running database migrations")
        create_tables()
        logger.info("[+] Database migrations completed")
    except Exception as e:
        logger.error(f"[-] Database migration failed: {e}", exc_info=True)
        raise DatabaseError(f"Database migration failed: {str(e)}") from e


def test_connection() -> bool:
    if _engine is None:
        logger.error("[-] Database not initialized")
        return False
    
    try:
        with _engine.connect() as conn:
            conn.execute("SELECT 1")
        logger.info("[+] Database connection test successful")
        return True
    except Exception as e:
        logger.error(f"[-] Database connection test failed: {e}")
        return False


def close_db() -> None:
    global _engine, _session_factory, _scoped_session_factory
    
    if _engine:
        logger.info("[+] Closing database connections")
        _engine.dispose()
        _engine = None
        _session_factory = None
        _scoped_session_factory = None
        logger.info("[+] Database connections closed")