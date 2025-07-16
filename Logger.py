import os
import time
import logging
from logging.handlers import RotatingFileHandler


#===============================================================================
# Class for logging based on application configuration
#===============================================================================
class Logger:
	def __init__(self, log_name: str, log_level: str="INFO", stdout_logging: bool=True, file_logging: bool=True, log_dir: str=".", log_size: int=10240, log_count: int=10):
		# Create our base logger object
		self.logger = logging.getLogger(log_name)
		self.logger.setLevel(logging.getLevelName(log_level))
		logging.Formatter.converter = time.gmtime

		if stdout_logging:
			# Add a stdout handler if enabled
			stdoutLogger = logging.StreamHandler()
			stdoutLogger.setFormatter(logging.Formatter('%(asctime)s (%(levelname)s) - %(message)s'))
			self.logger.addHandler(stdoutLogger)

			# Confirm that our stdout logger has been configured
			self.logger.debug(f'Stdout logging has been initiated and set to {log_level}')

		if file_logging:
			# Ensure we have write access to the logger location
			self.check_log_path(self.logger, log_dir)

			# Use a RotatingFileHandler for our file logger (log => log.1 => log.2 => ...)
			fileLogger = RotatingFileHandler(f"{log_dir}/{log_name}", maxBytes=log_size, backupCount=log_count)
			fileLogger.setFormatter(logging.Formatter('%(asctime)s (%(levelname)s) - %(message)s'))

			# Add both file and stdout handlers to the logger
			self.logger.addHandler(fileLogger)

			# Confirm that our file logger has been configured
			self.logger.debug(f'File logging to {log_dir}/{log_name} and set to {log_level}')


	def check_log_path(self, logger, log_dir):
		if os.path.exists(log_dir):
			if os.access(log_dir, os.W_OK):
				logger.debug(f'Log file path {log_dir} exists with write access')
				return True
			else:
				logger.critical(f'Log file path {log_dir} exists, but we do not have write access')
				os._exit(1)
		else:
			try:
				os.makedirs(log_dir)
				return True
			except Exception as e:
				logger.critical(f'Log file path {log_dir} does not exist, and it could not be created')
				os._exit(1)


	def get_logger(self):
		return self.logger


# Instantiate a shared instance of the Logger class
logger = Logger(log_name="logfile", log_level="INFO", stdout_logging=True, file_logging=True, log_dir=".", log_size=10240, log_count=10).get_logger()
