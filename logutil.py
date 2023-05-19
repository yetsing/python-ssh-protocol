import logging.config

config = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "web": {
            "format": "%(asctime)s %(levelname)s %(filename)s:%(lineno)d %(funcName)s | %(message)s"
        }
    },
    "handlers": {
        "stream": {
            "class": "logging.StreamHandler",
            "level": "DEBUG",
            "formatter": "web",
        },
    },
    "root": {
        "level": "DEBUG",
        "handlers": [
            "stream",
        ],
    },
}
logging.config.dictConfig(config)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger("pylog." + name)
