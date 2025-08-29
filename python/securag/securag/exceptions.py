

class FlaggedInputError(Exception):
    """Exception raised for errors in the input that has been flagged."""
    def __init__(self, message="Input has been flagged for review"):
        self.message = message


class FlaggedOutputError(Exception):
    """Exception raised for errors in the output that has been flagged."""
    def __init__(self, message="Output has been flagged for review"):
        self.message = message