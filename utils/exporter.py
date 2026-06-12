import json
import csv
import os
from typing import List, Dict, Any

class ReportExporter:
    @staticmethod
    def to_json(filepath: str, results: List[Dict[str, Any]], stats: Dict[str, Any]):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        serializable_stats = stats.copy()
        serializable_stats["start_time"] = str(stats["start_time"])
        serializable_stats["end_time"] = str(stats["end_time"])
        
        data = {"statistics": serializable_stats, "open_ports": results}
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4)

    @staticmethod
    def to_csv(filepath: str, results: List[Dict[str, Any]]):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        keys = ["port", "status", "service", "banner", "risk_level", "recommendation"]
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            for row in results:
                writer.writerow({k: row.get(k, "N/A") for k in keys})

    @staticmethod
    def to_txt(filepath: str, results: List[Dict[str, Any]], stats: Dict[str, Any]):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w') as f:
            f.write("==================================================\n")
            f.write("          ADVANCED PORT SCANNER REPORT           \n")
            f.write("==================================================\n")
            f.write(f"Scan Duration : {stats.get('duration')}\n")
            f.write(f"Total Scanned : {stats.get('total_scanned')}\n")
            f.write(f"Open Ports    : {stats.get('open_ports')}\n")
            f.write(f"OS Detection  : {stats.get('os_guess')}\n\n")
            f.write("Discovered Services:\n")
            for res in results:
                f.write(f"[-] Port {res['port']} ({res['service']}) - Status: {res['status']}\n")
                f.write(f"    Banner: {res['banner']}\n")
                f.write(f"    Risk: {res['risk_level']}\n")
                f.write(f"    Mitigation: {res['recommendation']}\n\n")