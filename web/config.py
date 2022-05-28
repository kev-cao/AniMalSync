# config.py
# Configuration classes for Flask app
###

# https://hackersandslackers.com/configure-flask-applications/
import boto3
import json
import os
from json import JSONDecodeError
from botocore.exceptions import ClientError
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

class Config:
    # App Config
    LOG_LEVEL = os.environ['LOG_LEVEL'].upper() \
        if 'LOG_LEVEL' in os.environ else 'INFO'
    LOG_FILE_PATH = os.path.join(
        basedir,
        os.environ['LOG_PATH'] if 'LOG_PATH' in os.environ else '/log'
    )
    LOG_FILE_NAME = os.environ['LOG_FILE_NAME'] \
        if 'LOG_FILE_NAME' in os.environ else 'app.log'

    FLASK_ENV = 'development'
    TESTING = True

    STATIC_FOLDER = 'static'
    TEMPLATES_FOLDER = 'templates'

    HOST_IP = os.environ['HOST_IP']
    HOST_PORT = int(os.environ['HOST_PORT'])
    APP_HOST = os.environ['APP_HOST_IP']
    SERVER_NAME = f"{HOST_IP}:{HOST_PORT}"

    # AWS Variables
    AWS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
    AWS_SECRET_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
    AWS_REGION_NAME = os.environ['AWS_REGION_NAME'] \
            if 'AWS_REGION_NAME' in os.environ else 'us-east-2'
    AWS_SNS_SYNC_TOPIC = 'arn:aws:sns:us-east-2:983398483317:AniMalSync-Sync-Notifier'
    AWS_USER_DYNAMODB_TABLE = 'AniMalSync-User-Data'
    AWS_LOG_DYNAMODB_TABLE = 'AniMalSync-Sync-Log'

    # Fetch app keys
    ssm = boto3.client('ssm', region_name=AWS_REGION_NAME)
    try:
        param = ssm.get_parameter(
            Name='/animalsync/keys',
            WithDecryption=True
        )['Value']
        app_keys = json.loads(param) 
        SECRET_KEY = app_keys['SECRET_KEY']
    except ClientError as e:
        print(f"Unable to retrieve AniMalSync secrets from SSM: {e}")
        raise e
    except (JSONDecodeError, KeyError) as e:
        print(f"Malformed parameter value in SSM: {e}")
        raise e


    
class DevelopmentConfig(Config):
    FLASK_ENV = 'development'
    LOG_LEVEL = 'DEBUG'
    DEBUG = True

class ProductionConfig(Config):
    FLASK_ENV = 'production'
    LOG_LEVEL = 'INFO'
    DEBUG = False
