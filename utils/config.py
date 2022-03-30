import json
import os

class UserConfig:
    def __init__(self):
        self.file = "../config/users.json"
        try:
            self.config = self.__load_json_file(self.file)
        except IOError:
            self.config = {}
            self.save()

    def save(self):
        """
        Saves the config file to disk.
        """
        self.__save_json_file(self.file, self.config)

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

    @classmethod
    def __load_json_file(cls, filename: str):
        """
        Loads a json file.

        Args:
            filename (string): The name of the file to load. Must include file extension.

        Returns:
            (json): The json file.

        Raises:
            IOError: If the file does not exist.
        """
        try:
            with open(os.path.join(os.path.dirname(__file__), filename), 'r') as f:
                return json.load(f)
        except IOError:
            raise IOError(f"Could not find {filename}.")

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

user_config = UserConfig()
