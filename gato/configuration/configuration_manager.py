import json
import os
import glob

class ConfigurationManager:
    """
    A singleton class to manage configuration data.

    Attributes:
        _instance (ConfigurationManager): The singleton instance of the ConfigurationManager class.
        _config (dict): The loaded configuration data.
    """

    _instance = None
    _config = None

    def __new__(cls, *args, **kwargs):
        """
        Overrides the default object creation behavior to implement the singleton pattern.

        Returns:
            ConfigurationManager: The singleton instance of the ConfigurationManager class.
        """
        if cls._instance is None:
            cls._instance = super(ConfigurationManager, cls).__new__(cls, *args, **kwargs)
            script_dir = os.path.dirname(os.path.realpath(__file__))
            json_files = glob.glob(os.path.join(script_dir, '*.json'))
            for file_path in json_files:
                cls._instance.load(file_path)
        return cls._instance

    def load(self, file_path):
        """
        Loads a JSON file and merges its entries into the existing configuration data.

        Args:
            file_path (str): The path to the JSON file to load.
        """
        with open(file_path, 'r') as f:
            config = json.load(f)
            if self._config is None:
                self._config = config
            else:
                self._config['entries'].update(config['entries'])

    def __getattr__(self, name):
        """
        Overrides the default attribute access behavior. If the attribute name matches the 'name' field in the configuration data, it returns the 'entries' field. Otherwise, it raises an AttributeError.

        Args:
            name (str): The name of the attribute to access.

        Returns:
            dict: The 'entries' field of the configuration data if the attribute name matches the 'name' field.

        Raises:
            AttributeError: If the attribute name does not match the 'name' field in the configuration data.
        """
        if self._config and name == self._config['name']:
            return self._config['entries']
        else:
            raise AttributeError(f"'ConfigurationManager' object has no attribute '{name}'")