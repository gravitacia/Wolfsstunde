import logging
import json
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime
from typing import Optional

_loggers: dict[str, logging.Logger] = {}


class FormatJSON(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "module": record.name,
            "message": record.getMessage(),
            "filename": record.filename,
            "lineno": record.lineno,
            "funcName": record.funcName,
        }
        
        if record.exc_info:
            log["exception"] = self.formatException(record.exc_info)
        
        if hasattr(record, "extra"):
            log["extra"] = record.extra
        
        return json.dumps(log, ensure_ascii=False)


class FormatText(logging.Formatter):
    def __init__(self):
        super().__init__(
            fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )


def _ensure() -> Path:
    log_dir = Path("build/logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


def setup_logger(
    name: str,
    level: int = logging.INFO,
    use_json: bool = True,
    log_to_console: bool = True,
    log_to_file: bool = True,
    console_level: Optional[int] = None,
    file_level: Optional[int] = None
) -> logging.Logger:

    logger = logging.getLogger(name)
    
    if logger.handlers:
        return logger 
    logger.setLevel(level)
    logger.propagate = False
    
    if log_to_file:
        log_dir = _ensure()
        log_file = log_dir / "app.log"
    else:
        log_file = None
    
    if console_level is None:
        console_level = logging.INFO
    if file_level is None:
        file_level = logging.DEBUG
    
    if log_to_file and log_file:
        file_handler = RotatingFileHandler(
            filename=str(log_file),
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8"
        )
        file_handler.setLevel(file_level)
        
        if use_json:
            file_formatter = FormatJSON()
        else:
            file_formatter = FormatText()
        
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    if log_to_console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(console_level)
        
        console_formatter = FormatText()
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
    
    return logger


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    if name in _loggers:
        return _loggers[name]
    
    logger = setup_logger(name, level=level)
    _loggers[name] = logger
    
    return logger


def set_log_level(logger_name: str, level: int) -> None:
    if logger_name in _loggers:
        logger = _loggers[logger_name]
        logger.setLevel(level)
        for handler in logger.handlers:
            handler.setLevel(level)


def disable_logger(logger_name: str) -> None:
    logger = logging.getLogger(logger_name)
    logger.disabled = True
    logger.propagate = False

_root_logger = setup_logger("Wolfsstunde", level=logging.INFO)