import sys
import os
from colorama import init, Fore, Style
from tabulate import tabulate
from core.scanner import PortScanner
from utils.exporter import ReportExporter
from gui.app import ScannerGUI

init(autoreset=True)

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]

def render_banner():
    print(Fore.CYAN + Style.BRIGHT + """
    ===================================================
    * ADVANCED PORT SCANNER & COMPLIANCE AUDIT   *
    ===================================================""")

def run_cli_scanner():
    render_banner()
    target = input("[?] Enter Target Hostname / IP: ").strip()
    
    print("\n[1] Scan Common Ports (Top 15 Profile)")
    print("[2] Scan Defined Custom Range (e.g. 1-1024)")
    print("[3] Read Multiple Hosts from external payload text file")
    choice = input("\n[?] Select Profile Target Mode: ").strip()

    ports = []
    if choice == "1":
        ports = COMMON_PORTS
    elif choice == "2":
        range_str = input("[?] Provide scope range (ex: 20-1000): ")
        start, end = map(int, range_str.split("-"))
        ports = list(range(start, end + 1))
    elif choice == "3":
        filepath = input("[?] Enter absolute path to host list file: ").strip()
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                hosts = [line.strip() for line in f if line.strip()]
            print(Fore.GREEN + f"[*] File read. Totaling {len(hosts)} target architectures.")
            # Map loop across all targets
            for h in hosts:
                execute_and_display_scan(h, COMMON_PORTS)
            return
        else:
            print(Fore.RED + "[-] File destination not found.")
            return
    else:
        print(Fore.RED + "[-] Bad input validation.")
        return

    execute_and_display_scan(target, ports)

def execute_and_display_scan(target: str, ports: list):
    print(Fore.YELLOW + f"\n[*] Initializing Audit Sequencing Pipeline targeting: {target}")
    scanner = PortScanner(target, ports)
    
    def cli_progress(current, total):
        sys.stdout.write(f"\r[*] Scan Progress Metric Pipeline: [{current}/{total}] Target Nodes")
        sys.stdout.flush()

    results, stats = scanner.run_scan(progress_callback=cli_progress)
    print("\n")

    # CLI Dashboard Rendering
    print(Fore.BLUE + Style.BRIGHT + "\n========= SECURITY DASHBOARD CAPSTONE METRICS =========")
    print(f"Target Resolved IP  : {scanner.target_ip} ({scanner.target_hostname})")
    print(f"Scan Duration Time  : {stats['duration']}")
    print(f"OS Passive Profile  : {stats['os_guess']}")
    print(f"Discovered Metrics  : Scanned {stats['total_scanned']} | Open: {stats['open_ports']} | Critical Risks: {stats['risky_found']}")
    
    if results:
        table_data = []
        for r in results:
            risk_colored = r["risk_level"]
            if r["risk_level"] in ["HIGH", "CRITICAL"]:
                risk_colored = Fore.RED + Style.BRIGHT + r["risk_level"] + Fore.RESET
            elif r["risk_level"] == "MEDIUM":
                risk_colored = Fore.YELLOW + r["risk_level"] + Fore.RESET
                
            table_data.append([r["port"], Fore.GREEN + r["status"] + Fore.RESET, r["service"], r["banner"][:30], risk_colored])
        
        print("\n" + tabulate(table_data, headers=["Port", "Status", "Service Profile", "Banner String", "Compliance Risk"], tablefmt="grid"))
        
        # Output configuration reports automatically
        out_txt = f"reports/scan_report_{scanner.target_ip}.txt"
        ReportExporter.to_txt(out_txt, results, stats)
        print(Fore.GREEN + f"\n[+] Production artifact exported successfully to {out_txt}")
    else:
        print(Fore.YELLOW + "\n[-] No open operational ports detected across structural profiles.")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--gui":
        app = ScannerGUI()
        app.mainloop()
    else:
        run_cli_scanner()