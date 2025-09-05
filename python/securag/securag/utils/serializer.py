

import os
import json
import pickle

from securag.exceptions import SerializationError


class SerializerUtils:

    @staticmethod
    def save_object(obj, path, filename):
        if isinstance(obj, (int, float, str, type(None))):
            return obj
        elif isinstance(obj, (list, dict)):
            try:
                path = os.path.join(path, filename) + ".json"
                with open(path, 'w') as json_file:
                    json.dump(obj, json_file)
                return "securag://" + filename + ".json"
            except (json.JSONDecodeError, TypeError) as e:
                path = os.path.join(path, filename) + ".pkl"
                with open(path, 'wb') as pkl_file:
                    pickle.dump(obj, pkl_file)
                return "securag://" + filename + ".pkl"
            except Exception as e:
                raise Exception(f"Failed to serialize field: {filename}. Error: {str(e)}")