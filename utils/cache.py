import json
import os
from time import time
from utils.config import config
from utils.logger import logger

class UserCache:
    def __init__(self):
        self.file = "../cache.json"
        try:
            self.cache = self.__load_json_file(self.file)
        except OSError as e:
            logger.warning("Could not open 'cache.json'. Recreating.")
            self.cache = {}

        # Add any missing users from config into cache.
        for user in config['users']:
            if user not in self.cache:
                self.cache[user] = {
                        'last_synced': int(time())
                        }
        self.save()

    def save(self):
        """
        Saves the cache file to disk.
        """
        self.__save_json_file(self.file, self.cache)

    def __setitem__(self, key, item):
        self.cache[key] = item

    def __getitem__(self, key):
        return self.cache[key]

    def __repr__(self):
        return repr(self.cache)

    def __len__(self):
        return len(self.cache)

    def __delitem__(self, key):
        del self.cache[key]

    def __contains__(self, key):
        return key in self.cache

    def has_key(self, key):
        return key in self.cache

    def keys(self):
        return self.cache.keys()

    def values(self):
        return self.cache.values()

    def items(self):
        return self.cache.items()

    @classmethod
    def __load_json_file(cls, filename: str):
        """
        Loads a json file.

        Args: filename (string): The name of the file to load. Must include file extension.  Returns:
            (json): The json file.

        Raises:
            IOError: If the file does not exist.
        """
        with open(os.path.join(os.path.dirname(__file__), filename), 'r') as f:
            return json.load(f)

    @classmethod
    def __save_json_file(cls, filename: str, data):
        """
        Saves data to the provided json filename.

        Args:
            filename (string): The name of the file to save to. Must include file extension.
            data (obj): The data to save to the file.
        """
        with open(os.path.join(os.path.dirname(__file__), filename), 'w') as f:
            json.dump(data, f, indent=4)

user_cache = UserCache()
