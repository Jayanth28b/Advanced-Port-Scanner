import logging
import os

def setup_logger() -> logging.Logger:
    """Configures centralized logging for error tracing."""
    logger = logging.getLogger("AdvancedPortScanner")
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        
        # File Handler
        log_dir = "reports"
        os.makedirs(log_dir, exist_ok=True)
        file_handler = logging.FileHandler(os.path.join(log_dir, "scanner.log"))
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    return logger