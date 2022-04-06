import json
import os
import boto3
from dotenv import load_dotenv
from utils.logger import logger

class Config:
    """
    Contains the configuration values for the application.
    """
    def __init__(self):
        load_dotenv()
        self.s3 = boto3.client('s3')
        self.bucket = 'anilist-to-mal-config'
        self.key = 'config.json'
        try:
            data = self.s3.get_object(Bucket=self.bucket, Key=self.key)
            self.config = json.loads(data['Body'].read())
        except Exception as e:
            logger.error(f"Could not load config file: {e}")
            raise e

    def save(self):
        """
        Saves the config file to AWS S3.
        """
        self.s3.put_object(Body=json.dumps(self.config),
                Bucket=self.bucket,
                Key=self.key)

    def __setitem__(self, key, item):
        self.config[key] = item

    def __getitem__(self, key):
        return self.config[key]

    def __repr__(self):
        return repr(self.config)

    def __len__(self):
        return len(self.config)

    def __delitem__(self, key):
        del self.config[key]

    def __contains__(self, key):
        return key in self.config

    def has_key(self, key):
        return key in self.config

    def keys(self):
        return self.config.keys()

    def values(self):
        return self.config.values()

    def items(self):
        return self.config.items()

config = Config()
