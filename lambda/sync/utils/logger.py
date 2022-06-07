import os
import logging

# Create logger (No other details as AWS configures their own)
logger = logging.getLogger()
logger.setLevel(os.environ['LOG_LEVEL'])
