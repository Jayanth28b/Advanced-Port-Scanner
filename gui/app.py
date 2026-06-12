import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
from core.scanner import PortScanner
from utils.exporter import ReportExporter

class ScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Advanced Network Port Scanner & Audit Tool")
        self.geometry("850x600")
        self.configure(bg="#2c3e50")
        self._build_ui()
        self.scanner = None

    def _build_ui(self):
        # Control Input Frame
        input_frame = tk.LabelFrame(self, text=" Configuration Parameters ", bg="#2c3e50", fg="white", font=("Arial", 10, "bold"))
        input_frame.pack(fill="x", padx=15, pady=10)

        tk.Label(input_frame, text="Target Host/IP:", bg="#2c3e50", fg="white").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.target_ent = tk.Entry(input_frame, width=25)
        self.target_ent.insert(0, "127.0.0.1")
        self.target_ent.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(input_frame, text="Port Specifier (e.g. 20-500 or 80,443):", bg="#2c3e50", fg="white").grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.ports_ent = tk.Entry(input_frame, width=25)
        self.ports_ent.insert(0, "21-445")
        self.ports_ent.grid(row=0, column=3, padx=5, pady=5)

        # Buttons
        self.start_btn = tk.Button(input_frame, text="Execute Scan", bg="#27ae60", fg="white", font=("Arial", 9, "bold"), command=self.start_scan)
        self.start_btn.grid(row=0, column=4, padx=10, pady=5)

        # Progress bar
        self.progress = ttk.Progressbar(self, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", padx=15, pady=5)

        # Results Display Window
        tree_frame = tk.Frame(self)
        tree_frame.pack(fill="both", expand=True, padx=15, pady=5)

        columns = ("port", "status", "service", "banner", "risk")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        self.tree.heading("port", text="Port Number")
        self.tree.heading("status", text="Status")
        self.tree.heading("service", text="Service Profile")
        self.tree.heading("banner", text="Banner Signature")
        self.tree.heading("risk", text="Risk Classification")
        
        self.tree.column("port", width=100, anchor="center")
        self.tree.column("status", width=100, anchor="center")
        self.tree.column("service", width=150)
        self.tree.column("banner", width=300)
        self.tree.column("risk", width=150, anchor="center")

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Export Options Footer
        footer = tk.Frame(self, bg="#2c3e50")
        footer.pack(fill="x", padx=15, pady=10)
        
        self.export_btn = tk.Button(footer, text="Export Comprehensive Audit Report", bg="#2980b9", fg="white", state="disabled", command=self.export_reports)
        self.export_btn.pack(side="right")

    def _update_progress(self, current, total):
        percentage = (current / total) * 100
        self.progress['value'] = percentage
        self.update_idletasks()

    def start_scan(self):
        target = self.target_ent.get().strip()
        port_raw = self.ports_ent.get().strip()

        if not target or not port_raw:
            messagebox.showerror("Validation Error", "Target and Port scope parameters cannot be left blank.")
            return

        # Simple string-to-list parsing logic
        ports = []
        try:
            if "-" in port_raw:
                start, end = map(int, port_raw.split("-"))
                ports = list(range(start, end + 1))
            elif "," in port_raw:
                ports = list(map(int, port_raw.split(",")))
            else:
                ports = [int(port_raw)]
        except ValueError:
            messagebox.showerror("Parsing Error", "Invalid port configuration format string.")
            return

        self.start_btn.config(state="disabled")
        self.tree.delete(*self.tree.get_children())
        self.progress['value'] = 0

        # Execute operations non-blocking on separate background daemon thread
        threading.Thread(target=self._execute_scan_thread, args=(target, ports), daemon=True).start()

    def _execute_scan_thread(self, target, ports):
        self.scanner = PortScanner(target, ports)
        results, stats = self.scanner.run_scan(progress_callback=self._update_progress)
        
        for r in results:
            self.tree.insert("", "end", values=(r["port"], r["status"], r["service"], r["banner"], r["risk_level"]))

        self.start_btn.config(state="normal")
        if results:
            self.export_btn.config(state="normal")
        messagebox.showinfo("Scan Completed", f"Audit Complete.\nOpen Ports Discovered: {stats['open_ports']}")

    def export_reports(self):
        if not self.scanner:
            return
        filepath = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv"), ("Text files", "*.txt")])
        if filepath:
            if filepath.endswith(".json"):
                ReportExporter.to_json(filepath, self.scanner.results, self.scanner.stats)
            elif filepath.endswith(".csv"):
                ReportExporter.to_csv(filepath, self.scanner.results)
            else:
                ReportExporter.to_txt(filepath, self.scanner.results, self.scanner.stats)
            messagebox.showinfo("Export Successful", f"Report saved to:\n{filepath}")