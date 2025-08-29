from . import Filter


class KeywordFilter(Filter):
    def __init__(self, name, keywords, description="", audit=False):
        super().__init__(name=name, description=description, audit=audit)
        self.keywords = keywords

    def run(self, query):
        identified = []

        matched = [keyword for keyword in self.keywords if keyword in query]
        if matched:
            identified.extend(matched)

        if len(identified) > 0:
            self.set_flag(True)

        audit_log = {
            "input": query,
            "output": query,
            "identified": identified,
        }

        self.log_audit(audit_log)

        return query
    
