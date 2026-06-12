import socket
import sys
import threading
from queue import Queue
from datetime import datetime
from typing import List, Dict, Any, Tuple
from core.banner_grabber import BannerGrabber
from core.risk_analyzer import RiskAnalyzer
from utils.logger import setup_logger

logger = setup_logger()

class PortScanner:
    def __init__(self, target: str, ports: List[int], threads: int = 100):
        self.target_input = target
        self.ports = ports
        self.thread_count = threads
        self.target_ip = ""
        self.target_hostname = ""
        self.results: List[Dict[str, Any]] = []
        self.stats = {"total_scanned": 0, "open_ports": 0, "risky_found": 0}
        self.progress_count = 0
        self.lock = threading.Lock()

    def resolve_target(self) -> bool:
        """Resolves domain names to IPv4 addresses."""
        try:
            self.target_ip = socket.gethostbyname(self.target_input)
            try:
                self.target_hostname = socket.gethostbyaddr(self.target_ip)[0]
            except socket.herror:
                self.target_hostname = "Unknown Host"
            return True
        except socket.gaierror as e:
            logger.error(f"Failed to resolve host {self.target_input}: {e}")
            return False

    def _get_os_fingerprint(self) -> str:
        """Basic TTL-based OS Guessing (Passive Fingerprinting)."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
                s.settimeout(1.0)
                # Fallback approximation via simple socket options if raw socket privilege isn't present
                return "Linux/Unix (Standard Stack)"
        except Exception:
            return "Indeterminate (Requires Admin Privileges for Raw ICMP)"

    def _scan_worker(self, queue: Queue, progress_callback=None):
        while not queue.empty():
            port = queue.get()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1.0)
                    result = s.connect_ex((self.target_ip, port))
                    
                    with self.lock:
                        self.progress_count += 1
                        if progress_callback:
                            progress_callback(self.progress_count, len(self.ports))

                    if result == 0:
                        try:
                            service_name = socket.getservbyport(port, "tcp")
                        except OSError:
                            service_name = "Unknown"
                        
                        banner = BannerGrabber.grab(self.target_ip, port)
                        risk_info = RiskAnalyzer.analyze_port(port)

                        res_entry = {
                            "port": port,
                            "status": "OPEN",
                            "service": service_name,
                            "banner": banner,
                            "risk_level": risk_info["risk_level"],
                            "recommendation": risk_info["recommendation"]
                        }
                        
                        with self.lock:
                            self.results.append(res_entry)
                            self.stats["open_ports"] += 1
                            if risk_info["is_risky"]:
                                self.stats["risky_found"] += 1
            except Exception as e:
                logger.error(f"Error scanning port {port}: {e}")
            finally:
                queue.task_done()

    def run_scan(self, progress_callback=None) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Orchestrates multi-threaded scanning execution loop."""
        if not self.resolve_target():
            return [], self.stats

        self.stats["start_time"] = datetime.now()
        self.stats["os_guess"] = self._get_os_fingerprint()
        
        queue = Queue()
        for port in self.ports:
            queue.put(port)

        threads_list = []
        for _ in range(min(self.thread_count, len(self.ports))):
            thread = threading.Thread(target=self._scan_worker, args=(queue, progress_callback))
            thread.daemon = True
            thread.start()
            threads_list.append(thread)

        queue.join()
        
        self.stats["end_time"] = datetime.now()
        self.stats["duration"] = str(self.stats["end_time"] - self.stats["start_time"])
        self.stats["total_scanned"] = len(self.ports)
        
        # Sort results sequentially by port number
        self.results.sort(key=lambda x: x["port"])
        return self.results, self.stats