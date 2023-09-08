import json
import logging
import logging.config
import logging.handlers
from pathlib import Path
from typing import Any


LOGGING_CONFIG = '''
{
    "version": 1,
    "formatters": {
        "simple": {
            "format": "%(levelname)s: %(message)s"
        },
        "detailed": {
            "format": "%(asctime)s: %(name)s: %(levelname)s: %(message)s"
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "INFO",
            "formatter": "simple"
        },
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": "logs/webhooks.log",
            "backupCount": 3,
            "maxBytes": 204800,
            "level": "DEBUG",
            "formatter": "detailed"
        }
    },
    "root": {
        "handlers": ["console", "file"],
        "level": "DEBUG"
    }
}
'''


def setup_logging(logging_config: dict[str, Any]) -> None:
    file_handler = logging_config.get("handlers", {}).get("file")
    if file_handler is not None:
        Path(file_handler["filename"]).parent.mkdir(parents=True, exist_ok=True)

    logging.config.dictConfig(logging_config)


setup_logging(json.loads(LOGGING_CONFIG))
