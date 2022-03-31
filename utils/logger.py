import os
import logging
from logging.handlers import RotatingFileHandler

# Create logger
log_file = os.path.join(os.path.dirname(__file__), "../log.out")
logger = logging.getLogger('logger')
logger.setLevel(logging.INFO)

# Create rotating file handler to limit log size.
handler = RotatingFileHandler(
        log_file,
        maxBytes=5 * 1024 * 1024,
        backupCount=1)

handler.setLevel(logging.INFO)
log_formatter = logging.Formatter("%(asctime)s - %(levelname)s: %(message)s")
handler.setFormatter(log_formatter)

logger.addHandler(handler)
