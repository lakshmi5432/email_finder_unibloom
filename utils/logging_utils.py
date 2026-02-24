from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path


DEFAULT_LOG_DIR = Path(__file__).resolve().parents[1] / "logs"
DEFAULT_LOG_FILE = DEFAULT_LOG_DIR / "app.log"


def configure_logging(
    *,
    level: str | int | None = None,
    log_file: str | Path = DEFAULT_LOG_FILE,
) -> None:
    """
    Configure app-wide logging once.

    Logs are written to:
    - console (INFO+)
    - rotating file (default: logs/app.log)
    """
    root_logger = logging.getLogger()
    if getattr(root_logger, "_email_finder_logging_ready", False):
        return

    if level is None:
        env_level = os.getenv("LOG_LEVEL", "INFO").strip().upper()
        resolved_level = getattr(logging, env_level, logging.INFO)
    elif isinstance(level, str):
        resolved_level = getattr(logging, level.strip().upper(), logging.INFO)
    else:
        resolved_level = level

    root_logger.setLevel(resolved_level)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler()
    console_handler.setLevel(resolved_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(
        filename=log_path,
        maxBytes=2_000_000,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setLevel(resolved_level)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    root_logger._email_finder_logging_ready = True
