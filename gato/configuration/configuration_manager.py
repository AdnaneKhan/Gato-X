import json
import os
import glob

class ConfigurationManager:
    _instance = None
    _config = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(ConfigurationManager, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self):
        script_dir = os.path.dirname(os.path.realpath(__file__))
        json_files = glob.glob(os.path.join(script_dir, '*.json'))
        for file_path in json_files:
            self.load(file_path)

    def load(self, file_path):
        with open(file_path, 'r') as f:
            config = json.load(f)
            if self._config is None:
                self._config = config
            else:
                self._config['entries'].update(config['entries'])

    def __getattr__(self, name):
        if self._config and name == self._config['name']:
            return self._config['entries']
        else:
            raise AttributeError(f"'ConfigurationManager' object has no attribute '{name}'")