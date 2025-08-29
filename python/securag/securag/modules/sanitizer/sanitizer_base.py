from abc import ABC, abstractmethod


class Sanitizer(ABC):
    def __init__(self, name, description="", audit=False):
        self.name = name
        self.description = description
        self.audit = audit

        self._id = None
        self._audit_log = None
        self._flag = False
        self._score = None

    @abstractmethod
    def run(self, user_input):
        pass

    def assign_id(self, id):
        self._id = id

    def get_id(self):
        return self._id
    
    def set_flag(self, flag):
        self._flag = flag

    def get_flag(self):
        return self._flag

    def set_score(self, score):
        self._score = score

    def get_score(self):
        return self._score

    def log_audit(self, log_entry):
        if not isinstance(log_entry, (dict, type(None))):
            raise ValueError("Audit log entry must be a dictionary.")
        self._audit_log = log_entry

    def get_audit_log(self):
        return self._audit_log

    def reset(self):
        self._audit_log = None
        self._flag = False
        self._score = None
