from abc import ABC, abstractmethod
from functools import wraps

import os
import shutil
from copy import deepcopy
import time

import re
import json
import pickle
from securag.modules import Module
import traceback
from typing import Literal

from datetime import datetime

from securag.exceptions import SerializationError
from securag.utils.serializer import SerializerUtils


class Pipe(ABC):
    @property
    @abstractmethod
    def pipe_type(self):
        pass

    @property
    def pipe_attributes(self) -> set:
        return set()

    def __init__(self,
                 name: str,
                 modules: list[Module],
                 description: str = "",
                 audit=False,
                 flagging_strategy: Literal["any", "all", "manual"] = "any",
                 ):
        if re.search(r'[<>:"/\\|?*\x00-\x1f]', name):
            raise ValueError(f"Invalid Pipe name '{name}': Pipe name cannot contain <>:\"/\\|?* or control characters.")
        self.name = name
        self.modules = modules
        self.description = description
        self.audit = audit
        self.flagging_strategy = flagging_strategy

        self._id = None
        self._audit_log = {
            "name": self.name,
            "id": self._id,
            "pipe_type": self.pipe_type,
            "log": {},
            "status": "noexec"
        }
        self._flag = False
        self._exec_time = None

    @abstractmethod
    def run(self, data):
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
        query_copy = deepcopy(query)
        try:
            self.reset()
            result = self.run(query_copy)
            self.log_audit({"input": query_copy, "output": result}, level="log")
            self.log_audit({"status": "success", "flag": self.get_flag(), "logged_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}, level="main")
            return result
        except Exception as e:
            self.log_audit({"message": str(e), "traceback": traceback.format_exc()}, level="log")
            self.log_audit({"status": "error", "flag": self.get_flag(), "logged_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}, level="main")
            return query
            return query

    def __call__(self, query, *args, **kwds):
        return self._run(query, *args, **kwds)

    def assign_id(self, id):
        self._id = id

    def get_id(self):
        return self._id

    def get_name(self):
        return self.name

    def set_flag(self, flag=None):
        if self.flagging_strategy == "manual" and flag is not None and isinstance(flag, bool):
            self._flag = flag
        elif self.flagging_strategy == "any":
            self._flag = any(module.get_flag() for module in self.modules)
        elif self.flagging_strategy == "all":
            self._flag = all(module.get_flag() for module in self.modules)

    def _force_set_flag(self, flag):
        self._flag = flag

    def get_flag(self):
        return self._flag

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

    def get_audit_logs(self):
        if not self.audit:
            return self._audit_log

        audit_logs = deepcopy(self._audit_log)

        module_logs = []
        for module in self.modules:
            module_logs.append(module.get_audit_log())

        audit_logs["modules"] = module_logs

        return audit_logs

    def reset(self):
        self._audit_log = {
            "name": self.name,
            "id": self._id,
            "pipe_type": self.pipe_type,
            "log": {},
            "status": "noexec"
        }
        self._flag = False
        self._exec_time = None

        for module in self.modules:
            module.reset()

    def initialize_modules(self):
        names = set()
        for i, module in enumerate(self.modules):
            if module.get_name() in names:
                raise ValueError(
                    f"Two or more modules have the same name: '{module.get_name()}' in pipe '{self.name}'")
            names.add(module.get_name())
            module.assign_id(i+1)
            module.reset()

    def flagged_response(self):
        if self.get_flag():
            return "\n".join([module.flagged_response() for module in self.modules if module.get_flag()])
        return ""
    
    def to_json(self, 
                path: str,
                raise_on_warnings: bool = True):
        pipe_path = os.path.join(path, self.name)
        if os.path.exists(pipe_path):
            shutil.rmtree(pipe_path)
        os.makedirs(pipe_path, exist_ok=True)

        json_dict = {
            "name": SerializerUtils.save_object(self.name, pipe_path, "name"),
            "description": SerializerUtils.save_object(self.description, pipe_path, "description"),
            "audit": SerializerUtils.save_object(self.audit, pipe_path, "audit"),
            "flagging_strategy": SerializerUtils.save_object(self.flagging_strategy, pipe_path, "flagging_strategy"),
            "pipe_type": SerializerUtils.save_object(self.pipe_type, pipe_path, "pipe_type"),
            "_id": SerializerUtils.save_object(self._id, pipe_path, "_id"),
            "self._audit_log": SerializerUtils.save_object(self._audit_log, pipe_path, "self._audit_log"),
            "self._flag": SerializerUtils.save_object(self._flag, pipe_path, "self._flag"),
            "self._exec_time": SerializerUtils.save_object(self._exec_time, pipe_path, "self._exec_time"),
            "modules": [module.to_json(os.path.join(path, self.name), raise_on_warnings) for module in self.modules],
        }

        for attribute in self.pipe_attributes:
            if not hasattr(self, attribute):
                raise SerializationError(f"Failed to serialize Pipe: {self.__class__.__name__}.{self.name}.{attribute}. Field is missing.")

            value = getattr(self, attribute)
            try:
                json_dict[attribute] = SerializerUtils.save_object(value, pipe_path, attribute)
            except SerializationError as e:
                raise SerializationError(f"Failed to serialize Pipe: {self.__class__.__name__}.{self.name}.{attribute}. Error: {str(e)}")
        
        return json_dict
    

    def __repr__(self):
        return f"<Pipe name={self.name} id={self._id} type={self.pipe_type} modules={len(self.modules)} flag={self._flag}>"