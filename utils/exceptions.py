class FrameworkError(Exception):
    def __init__(self, message: str, code: int = None):
        super().__init__(message)
        self.message = message
        self.code = code

    def __str__(self):
        parts = [f"[-] Error: {self.message}"]
        if self.code is not None:
            parts.append(f"[-] Error Code: {self.code}")
        return "\n".join(parts)

class ValidationError(FrameworkError):
    ERROR = 1000 
    def __init__(self, message: str, code: int = None):
        if code is None:
            code = self.ERROR
        super().__init__(message, code)

class EncryptionError(FrameworkError):
    ERROR = 1100
    def __init__(self, message: str, code: int = None):
        if code is None:
            code = self.ERROR
        super().__init__(message, code)

class DatabaseError(FrameworkError):
    ERROR = 1200
    def __init__(self, message: str, code: int = None):
        if code is None:
            code = self.ERROR
        super().__init__(message, code)

class AgentError(FrameworkError):
    ERROR = 1300
    def __init__(self, message: str, code: int = None):
        if code is None:
            code = self.ERROR
        super().__init__(message, code)

class ModuleError(FrameworkError):
    ERROR = 1400
    def __init__(self, message: str, code: int = None):
        if code is None:
            code = self.ERROR
        super().__init__(message, code)
