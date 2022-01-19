import logging
import os
import sys
from logging.handlers import RotatingFileHandler

from .config import config


def _setLogger_(console=False):
    my_logger = logging.getLogger(os.path.basename(sys.argv[0]))
    my_logger.setLevel(config['loggingLevel'])
    handler = RotatingFileHandler(config['logFileName'], maxBytes=config['logFileSize'],
                                  backupCount=config['logMaxFiles'])
    formatter = logging.Formatter('{asctime} {name} {levelname}: {message}', style='{')
    handler.setFormatter(formatter)
    my_logger.addHandler(handler)
    if console:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(formatter)
        my_logger.addHandler(handler)

    return my_logger


logger = _setLogger_(config['loggingToConsole'])
