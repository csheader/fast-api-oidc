import os


class Logger:
    """
    A Logger class that intercepts logging method calls and defaults to print if no logger is provided.

    This class allows for flexible logging by using a provided logger object. If no logger is provided,
    it defaults to printing messages to the console. It supports common logging methods such as 'info',
    'warning', and 'error', and respects debug mode based on the DEBUG_MODE environment variable.

    Attributes:
        logger (object): An optional logger object that should have methods like 'info', 'warning', etc.
        debug (bool): Whether to enable debug logging.
    """

    def __init__(self, logger=None):
        self.logger = logger
        self.debug = os.getenv("DEBUG_MODE", "False").lower() == "true"

    def __getattr__(self, name):
        """
        Intercepts logger method calls and defaults to print if no logger is provided.

        :param name: The name of the logging method (e.g., 'info', 'warning', 'error').
        :return: A function that logs the message.
        """
        def log_method(message: str):
            if name == 'debug' and not self.debug:
                return

            if self.logger and hasattr(self.logger, name):
                getattr(self.logger, name)(message)
            else:
                prefix = name.upper() if name in ['warning', 'error', 'debug'] else ''
                print(f"{prefix}: {message}" if prefix else message)

        return log_method
