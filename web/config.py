# config.py
# Configuration classes for Flask app
###

# https://hackersandslackers.com/configure-flask-applications/
import boto3
import json
import os
from json import JSONDecodeError
from botocore.exceptions import ClientError

class Config:
    """
    Base configuration class for Flask application. Contains various environment variables.
    """
    # App Config
    basedir = os.path.abspath(os.path.dirname(__file__))
    LOG_LEVEL = os.environ['LOG_LEVEL'].upper() \
        if 'LOG_LEVEL' in os.environ else 'INFO'
    LOG_FILE_PATH = os.path.join(
        basedir,
        os.environ['LOG_PATH'] if 'LOG_PATH' in os.environ else 'log/'
    )
    LOG_FILE_NAME = os.environ['LOG_FILE_NAME'] \
        if 'LOG_FILE_NAME' in os.environ else 'app.log'

    FLASK_ENV = 'development'

    STATIC_FOLDER = 'static'
    TEMPLATES_FOLDER = 'templates'

    HOST_PORT = int(os.environ['HOST_PORT'])
    APP_HOST = os.environ['APP_HOST_IP']

    APP_EMAIL = 'animalsync.app@gmail.com'

    # AWS Variables
    AWS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
    AWS_SECRET_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
    AWS_REGION_NAME = os.environ['AWS_REGION_NAME'] \
        if 'AWS_REGION_NAME' in os.environ else 'us-east-2'
    AWS_SNS_SYNC_TOPIC = 'arn:aws:sns:us-east-2:983398483317:AniMalSync-Sync-Notifier'
    AWS_USER_DYNAMODB_TABLE = 'AniMalSync-User-Data'
    AWS_LOG_DYNAMODB_TABLE = 'AniMalSync-Sync-Log'
    AWS_EMAIL_LAMBDA = 'AniMalSync-OAuth-Emailer'
    AWS_SFN_SYNC = 'arn:aws:states:us-east-2:983398483317:stateMachine:AniMalSync-Sync-Publish'
    VERIF_EMAIL_TEMPLATE = 'AniMalSync_Email_Verification'
    RESET_PASSWORD_EMAIL_TEMPLATE = 'AniMalSync_MAL_Reset_Password'

    # Fetch app keys
    ssm = boto3.client('ssm', region_name=AWS_REGION_NAME)
    try:
        param = ssm.get_parameter(
            Name='/animalsync/keys',
            WithDecryption=True
        )['Parameter']['Value']
        app_keys = json.loads(param)
        SECRET_KEY = app_keys['APP_SECRET_KEY']
        RECAPTCHA_PRIVATE_KEY = app_keys[
            f'{"DEV_" if FLASK_ENV == "development" else ""}RECAPTCHA_PRIVATE_KEY'
        ]
        RECAPTCHA_PUBLIC_KEY = app_keys[
            f'{"DEV_" if FLASK_ENV == "development" else ""}RECAPTCHA_PUBLIC_KEY'
        ]
    except ClientError as e:
        print(f"Unable to retrieve AniMalSync secrets from SSM: {e}")
        raise e
    except (JSONDecodeError, KeyError) as e:
        print(f"Malformed parameter value in SSM: {e}")
        raise e

    # Fetch MAL keys
    try:
        param = ssm.get_parameter(
            Name='/mal_client/keys',
            WithDecryption=True
        )['Parameter']['Value']
        mal_keys = json.loads(param)
        MAL_CLIENT_ID = mal_keys['MAL_CLIENT_ID']
        MAL_CLIENT_SECRET = mal_keys['MAL_CLIENT_SECRET']
    except ClientError as e:
        print(f"Unable to retrieve MAL secrets from SSM: {e}")
        raise e
    except (JSONDecodeError, KeyError) as e:
        print(f"Malformed parameter value in SSM: {e}")
        raise e


class DevelopmentConfig(Config):
    """
    Flask app configuration class for development environment.
    """
    print(f"Using development config")
    FLASK_ENV = 'development'
    LOG_LEVEL = 'DEBUG'
    DEBUG = True
    TESTING = True


class ProductionConfig(Config):
    """
    Flask app configuration class for production environment.
    """
    print(f"Using production config")
    FLASK_ENV = 'production'
    LOG_LEVEL = 'INFO'
    DEBUG = False
    TESTING = False
