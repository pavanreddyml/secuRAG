from abc import ABC, abstractmethod

import time
from functools import wraps
import traceback
from datetime import datetime
from copy import deepcopy

class Module(ABC):
    def __init__(self, 
                 name, 
                 description="", 
                 audit=False
                 ):
        self.name = name
        self.description = description
        self.audit = audit

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
            start = time.time()
            try:
                return func(self, *args, **kwargs)
            finally:
                self._exec_time = (time.time() - start) * 1000
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
