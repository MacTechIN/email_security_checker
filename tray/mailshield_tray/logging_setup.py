"""회전 로그 설정. 개인정보 원문은 기록하지 않는다(scanner가 마스킹)."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from .paths import log_path

MAX_BYTES = 5 * 1024 * 1024
BACKUP_COUNT = 5


def configure_logging(level: int = logging.INFO, console: bool = False) -> None:
    root = logging.getLogger()
    if any(isinstance(h, RotatingFileHandler) for h in root.handlers):
        return
    root.setLevel(level)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(threadName)s %(message)s")
    file_handler = RotatingFileHandler(log_path(), maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT, encoding="utf-8")
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)
    if console:
        stream = logging.StreamHandler()
        stream.setFormatter(formatter)
        root.addHandler(stream)
    # 서드파티 잡음 억제
    for noisy in ("imapclient", "urllib3", "google", "PIL"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
