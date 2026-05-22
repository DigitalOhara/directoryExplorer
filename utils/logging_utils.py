"""
Logging configuration: rotating file handlers + coloured console output.
"""

import logging
import logging.handlers
import os
from pathlib import Path


COLORS = {
    "DEBUG":    "\033[36m",   # cyan
    "INFO":     "\033[32m",   # green
    "WARNING":  "\033[33m",   # yellow
    "ERROR":    "\033[31m",   # red
    "CRITICAL": "\033[35m",   # magenta
    "RESET":    "\033[0m",
}


class ColorFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        color = COLORS.get(record.levelname, COLORS["RESET"])
        reset = COLORS["RESET"]
        record.levelname = f"{color}{record.levelname:<8}{reset}"
        return super().format(record)


def setup_logging(
    log_dir: str,
    verbose: bool = False,
    log_name: str = "directoryExplorer",
) -> logging.Logger:
    level = logging.DEBUG if verbose else logging.INFO
    logger = logging.getLogger(log_name)
    logger.setLevel(logging.DEBUG)

    if logger.handlers:
        return logger

    Path(log_dir).mkdir(parents=True, exist_ok=True)

    # Rotating file handler (keeps last 5 × 10 MB)
    log_file = os.path.join(log_dir, f"{log_name}.log")
    fh = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(
        logging.Formatter(
            "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(
        ColorFormatter(
            "%(asctime)s  %(levelname)s  %(message)s",
            datefmt="%H:%M:%S",
        )
    )

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


def get_logger(name: str = "directoryExplorer") -> logging.Logger:
    return logging.getLogger(name)
