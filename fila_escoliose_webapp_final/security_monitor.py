import logging
from datetime import datetime

class SecurityMonitor:
    def __init__(self):
        self.logger = logging.getLogger('security')
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler('security.log')
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
        self.logger.addHandler(handler)
    
    def log_activity(self, user, action, ip_address, status):
        self.logger.info(f"User: {user}, Action: {action}, IP: {ip_address}, Status: {status}")