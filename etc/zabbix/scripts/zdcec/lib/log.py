import logging
from logging.handlers import RotatingFileHandler
import sys
import os

from lib.config import config

def _setLogger_(console=False):
    logger = logging.getLogger(os.path.basename(sys.argv[0]))
    logger.setLevel(config['loggingLevel'])
    handler = RotatingFileHandler(config['logFileName'], maxBytes=config['logFileSize'], backupCount=config['logMaxFiles'])
    formatter = logging.Formatter('{asctime} {name} {levelname}: {message}', style='{')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    if console:
      handler = logging.StreamHandler(sys.stderr)
      handler.setFormatter(formatter)
      logger.addHandler(handler)
    
    return logger


logger = _setLogger_(config['loggingToConsole'])