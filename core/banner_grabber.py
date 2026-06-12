import socket
from utils.logger import setup_logger

logger = setup_logger()

class BannerGrabber:
    @staticmethod
    def grab(ip: str, port: int, timeout: float = 1.0) -> str:
        """Attempts to grab the service banner from an open port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                # Send a generic request payload for protocols requiring stimulus (like HTTP)
                if port in [80, 443, 8080]:
                    s.sendall(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner.replace('\n', ' ').replace('\r', '')
        except Exception:
            return "Unknown Service"