import logging
from pathlib import Path


class Logger:

    def __init__(self, config):

        log_directory = Path(config.get("logging", "log_directory"))

        log_directory.mkdir(exist_ok=True)

        logfile = log_directory / config.get("logging", "log_file")

        logging.basicConfig(

            filename=logfile,

            level=logging.INFO,

            format="%(asctime)s | %(levelname)s | %(message)s"

        )

        self.logger = logging.getLogger("AKRDFAS")

    def info(self, message):

        self.logger.info(message)

    def warning(self, message):

        self.logger.warning(message)

    def error(self, message):

        self.logger.error(message)