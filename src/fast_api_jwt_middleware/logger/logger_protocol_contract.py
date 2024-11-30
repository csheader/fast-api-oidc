from typing import Protocol, runtime_checkable

@runtime_checkable
class LoggerProtocol(Protocol):
    """
    LoggerProtocol defines a standard interface for logging operations.

    This protocol outlines the methods that any logger implementation should provide.
    It is designed to ensure that any logger can be used interchangeably in the application,
    as long as it adheres to this interface.

    Methods:
    - debug(msg: str, *args, **kwargs) -> None: 
        Logs a message with level DEBUG.
        
    - info(msg: str, *args, **kwargs) -> None: 
        Logs a message with level INFO.
        
    - warning(msg: str, *args, **kwargs) -> None: 
        Logs a message with level WARNING.
        
    - error(msg: str, *args, **kwargs) -> None: 
        Logs a message with level ERROR.
        
    - critical(msg: str, *args, **kwargs) -> None: 
        Logs a message with level CRITICAL.
    """
    def debug(self, msg: str, *args, **kwargs) -> None:
        ...
    def info(self, msg: str, *args, **kwargs) -> None:
        ...
    def warning(self, msg: str, *args, **kwargs) -> None:
        ...
    def error(self, msg: str, *args, **kwargs) -> None:
        ...
    def critical(self, msg: str, *args, **kwargs) -> None:
        ...