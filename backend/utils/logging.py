import os
import logging
from logging.handlers import RotatingFileHandler
import time

def configure_logging(app, log_level=None):
    """
    Configure application logging with both file and console handlers
    
    Args:
        app: Flask application instance
        log_level: Logging level (default: app.config.get('LOG_LEVEL', 'INFO'))
    """
    if log_level is None:
        log_level = app.config.get('LOG_LEVEL', 'INFO')
        
    # Convert string log level to actual log level
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO
    
    # Create logs directory if it doesn't exist
    log_dir = os.path.join(app.root_path, 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    # Set up log file path with date
    log_file = os.path.join(log_dir, f'app-{time.strftime("%Y%m%d")}.log')
    
    # Set up root logger
    logger = logging.getLogger()
    logger.setLevel(numeric_level)
    
    # Clear any existing handlers to avoid duplicates
    if logger.handlers:
        logger.handlers.clear()
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create file handler for logging to file
    file_handler = RotatingFileHandler(
        log_file, maxBytes=10485760, backupCount=10  # 10MB per file, keep 10 files
    )
    file_handler.setLevel(numeric_level)
    file_handler.setFormatter(formatter)
    
    # Create console handler for logging to console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)
    
    # Add the handlers to the root logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    # Log Flask and Werkzeug through the app logger
    for logger_name in ['werkzeug', 'flask.app']:
        module_logger = logging.getLogger(logger_name)
        module_logger.handlers = []  # Remove default handlers
        module_logger.propagate = True
    
    app.logger.info(f"Logging configured with level: {log_level}")
    
    return logger
