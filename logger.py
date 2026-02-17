import datetime
import os

app_name = 'logger.py'


class WSLogger:
    _instance = None
    _initialized = False

    def __init__(self, source: str) -> None:
        self.source = source
        if not WSLogger._initialized:
            self._setup_verbosity()
            WSLogger._initialized = True

    def _setup_verbosity(self) -> None:
        _verbosity = os.getenv('VERBOSITY', '1')
        try:
            self.verbosity = int(_verbosity)
        except ValueError:
            message = f"Invalid VERBOSITY value: {_verbosity}, defaulting to 1"
            self.log_message(message, 0)
            self.verbosity = 1

        if self.verbosity not in (0, 1, 2):
            message = f"Invalid VERBOSITY value: {self.verbosity}, defaulting to 1"  # NOQA: E501
            self.log_message(message, 0)
            self.verbosity = 1

    def log_message(self, message: str, level: int) -> None:
        '''
        Prints a message to the console with a timestamp and source label.

        :param message: The message payload
        :param source: Name of the application component generating the message
        :param level: Verbosity level of the message (0=error, 1=normal, 2=debug). Messages with a level higher than the configured verbosity will not be printed.
        '''  # NOQA: E501
        # timestamp formatted as YYYY-MM-DD HH:MM:SS.mmm
        if level > self.verbosity:
            return
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]  # NOQA: E501
        print(f"[{timestamp}] [{self.source}] {message}")
