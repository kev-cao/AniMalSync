import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask

configs = {
    'development': 'config.DevelopmentConfig',
    'production': 'config.ProductionConfig'
}

log_levels = {
    'CRITICAL': logging.CRITICAL,
    'ERROR': logging.ERROR,
    'WARNING': logging.WARNING,
    'INFO': logging.INFO,
    'DEBUG': logging.DEBUG
}

app = Flask(__name__)
app.config.from_object(configs[os.environ['ENV']])
app.url_map.strict_slashes = False

# Configure Logging

# Set up rotating file handler
if not os.path.exists(app.config['LOG_FILE_PATH']):
    os.makedirs(app.config['LOG_FILE_PATH'])
log_file = os.path.join(
    app.config['LOG_FILE_PATH'], app.config['LOG_FILE_NAME'])
log_file_handler = RotatingFileHandler(log_file, maxBytes=1024 * 1024, backupCount=5)

# Set up stream handler
log_stream_handler = logging.StreamHandler()

# Set up log level and format
log_level = log_levels[app.config['LOG_LEVEL']]

if log_level >= logging.INFO:
    log_format = '%(asctime)s %(levelname)s: %(message)s f'
else:
    log_format = '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'

log_file_handler.setLevel(log_level)
log_stream_handler.setLevel(log_level)

log_file_handler.setFormatter(logging.Formatter(log_format))
log_stream_handler.setFormatter(logging.Formatter(log_format))

app.logger.addHandler(log_file_handler)
app.logger.addHandler(log_stream_handler)
app.logger.setLevel(log_level)

app.logger.info(f"Using {configs[os.environ['ENV']]}")

import auth
import views
