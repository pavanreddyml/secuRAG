from abc import ABC, abstractmethod
import os
import shutil

import warnings

import re
import time
from functools import wraps
import traceback
from datetime import datetime
from copy import deepcopy

from securag.exceptions import SerializationError
from securag.utils.serializer import SerializerUtils
class Module(ABC):
    @property
    def module_attributes(self) -> set:
        return set()

    def __init__(self, 
                 name, 
                 description="", 
                 audit=False,
                 default_flagged_response="The query was flagged."
                 ):
        if re.search(r'[<>:"/\\|?*\x00-\x1f]', name):
            raise ValueError(f"Invalid Pipe name '{name}': Pipe name cannot contain <>:\"/\\|?* or control characters.")
        self.name = name

        self.description = description
        self.audit = audit
        self.default_flagged_response = default_flagged_response

        self._id = None
        self._audit_log = {
            "name": self.name,
            "id": self._id,
            "log": {},
            "status": "noexec"
        }
        self._flag = False
        self._score = None
        self._exec_time = None

    @abstractmethod
    def run(self, query):
        pass

    @staticmethod
    def _time_logger(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            start = time.perf_counter()
            try:
                return func(self, *args, **kwargs)
            finally:
                self._exec_time = (time.perf_counter() - start) * 1000
                self.log_audit({"execution_time": self._exec_time}, level="main")
        return wrapper
    
    @_time_logger
    def _run(self, query, *args, **kwargs):
        try:
            self.reset()
            result = self.run(query)
            self.log_audit({"status": "success", "flag": self.get_flag(), "score": self.get_score(), "logged_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}, level="main")
            return result
        except Exception as e:
            self.set_flag(True)
            self.log_audit({"message": str(e), "traceback": traceback.format_exc()}, level="log")
            self.log_audit({"status": "error", "flag": self.get_flag(), "score": self.get_score(), "logged_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}, level="main")
            return query
        
    def __call__(self, query, *args, **kwds):
        return self._run(query, *args, **kwds)
        
    def assign_id(self, id):
        self._id = id

    def get_id(self):
        return self._id
    
    def get_name(self):
        return self.name

    def set_flag(self, flag):
        self._flag = flag

    def get_flag(self):
        return self._flag

    def set_score(self, score):
        self._score = score

    def get_score(self):
        return self._score

    def get_time(self):
        return self._exec_time
    
    def log_audit(self, value, level="log"):
        if not self.audit:
            self._audit_log["status"] = "disabled"
            return

        if level not in ["log", "main"]:
            raise ValueError("Invalid log level. Must be 'log' or 'main'.")
        
        if not isinstance(value, dict):
                raise ValueError("Audit log entry must be a dict.")
        
        if level == "log":
            self._audit_log["log"] = {**self._audit_log["log"], **value}
        elif level == "main":
            self._audit_log = {**self._audit_log, **value}

    def get_audit_log(self):
        return self._audit_log

    def reset(self):
        self._audit_log = {
            "name": self.name,
            "id": self._id,
            "log": {},
            "status": "noexec"
        }
        self._flag = False
        self._score = None
        self._exec_time = None

    def flagged_response(self):
        if self.get_flag():
            return self.default_flagged_response
        return ""
    
    def to_json(self, 
                path: str,
                raise_on_warnings: bool = True):
        module_path = os.path.join(path, self.name)
        if os.path.exists(module_path):
            shutil.rmtree(module_path)
        os.makedirs(module_path, exist_ok=True)

        if (self.module_attributes is None or len(self.module_attributes) == 0) and raise_on_warnings:
            raise SerializationError(f"Failed to serialize object: {self.__class__.__name__}. module_attributes is empty. If this is intended and attributes are empty, set raise_on_warnings to False.")
        else:
            warnings.warn(f"Warning: module_attributes is empty for {self.__class__.__name__}. If this is intended and attributes are empty, set raise_on_warnings to False.", UserWarning)

        json_dict = {
            "name": SerializerUtils.save_object(self.name, module_path, "name"),
            "description": SerializerUtils.save_object(self.description, module_path, "description"),
            "audit": SerializerUtils.save_object(self.audit, module_path, "audit"),
            "default_flagged_response": SerializerUtils.save_object(self.default_flagged_response, module_path, "default_flagged_response"),
            "self._id": SerializerUtils.save_object(self._id, module_path, "self._id"),
            "self._audit_log": SerializerUtils.save_object(self._audit_log, module_path, "self._audit_log"),
            "self._flag": SerializerUtils.save_object(self._flag, module_path, "self._flag"),
            "self._exec_time": SerializerUtils.save_object(self._exec_time, module_path, "self._exec_time"),
            "self._score": SerializerUtils.save_object(self._score, module_path, "self._score"),
        }

        for attribute in self.module_attributes:
            if not hasattr(self, attribute):
                raise SerializationError(f"Failed to serialize Module: {self.__class__.__name__}.{self.name}.{attribute}. Field is missing.")

            value = getattr(self, attribute)
            try:
                json_dict[attribute] = SerializerUtils.save_object(value, module_path, attribute)
            except SerializationError as e:
                raise SerializationError(f"Failed to serialize Module: {self.__class__.__name__}.{self.name}.{attribute}. Error: {str(e)}")
        
        return json_dict
