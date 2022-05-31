import os
import logging

# Create logger
logger = logging.getLogger('sync')
logger.setLevel(os.environ['LOG_LEVEL'])

handler = logging.StreamHandler()
handler.setLevel(os.environ['LOG_LEVEL'])
log_formatter = logging.Formatter("%(asctime)s - %(levelname)s: %(message)s")
handler.setFormatter(log_formatter)

logger.addHandler(handler)
