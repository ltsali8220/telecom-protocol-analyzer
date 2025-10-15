import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import socket
import threading
import time
import json
from datetime import datetime
import struct
import ipaddress

class TelecomProtocolAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Telecom Protocol Analyzer - GTP/SCTP Security Tool")
        self.root.geometry("900x700")
        self.root.configure(bg='#2b2b2b')
        
        # Analysis state
        self.is_analyzing = False
        self.capture_thread = None
        
        # Create GUI
        self.create_widgets()
        
        # Protocol definitions
        self.gtp_versions = {
            1: "GTPv1",
            2: "GTPv2"
        }
        
        self.sctp_chunk_types = {
            0: "DATA",
            1: "INIT",
            2: "INIT_ACK",
            3: "SACK",
            4: "HEARTBEAT",
            5: "HEARTBEAT_ACK",
            6: "ABORT",
            7: "SHUTDOWN",
            8: "SHUTDOWN_ACK",
            9: "ERROR"
        }
        
        self.vulnerability_patterns = [
            "Buffer overflow in message length",
            "Invalid sequence number",
            "Malformed chunk header",
            "Unsupported parameter",
            "Protocol version mismatch",
            "Replay attack detected",
            "Flooding attempt",
            "Invalid checksum"
        ]

    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = tk.Label(main_frame, text="Telecom Protocol Analyzer", 
                              font=('Arial', 16, 'bold'), fg='white', bg='#2b2b2b')
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Protocol Selection
        ttk.Label(main_frame, text="Protocol:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.protocol_var = tk.StringVar(value="GTP")
        protocol_combo = ttk.Combobox(main_frame, textvariable=self.protocol_var, 
                                     values=["GTP", "SCTP"], state="readonly", width=15)
        protocol_combo.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # Target Configuration
        ttk.Label(main_frame, text="Target IP:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.ip_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(main_frame, textvariable=self.ip_var, width=20).grid(row=2, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(main_frame, text="Port:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.port_var = tk.StringVar(value="2123")
        ttk.Entry(main_frame, textvariable=self.port_var, width=20).grid(row=3, column=1, sticky=tk.W, pady=5)
        
        # Analysis Type
        ttk.Label(main_frame, text="Analysis Type:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.analysis_var = tk.StringVar(value="Passive Monitoring")
        analysis_combo = ttk.Combobox(main_frame, textvariable=self.analysis_var,
                                     values=["Passive Monitoring", "Active Scanning", "Fuzz Testing", "Vulnerability Assessment"],
                                     state="readonly", width=20)
        analysis_combo.grid(row=4, column=1, sticky=tk.W, pady=5)
        
        # Control Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, columnspan=3, pady=10)
        
        self.start_btn = ttk.Button(button_frame, text="Start Analysis", command=self.start_analysis)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(button_frame, text="Stop Analysis", command=self.stop_analysis, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Save Results", command=self.save_results).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear Log", command=self.clear_log).pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        # Results Notebook
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=7, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        
        # Packet Log Tab
        log_frame = ttk.Frame(notebook, padding="5")
        self.packet_log = scrolledtext.ScrolledText(log_frame, height=15, width=80, bg='#1e1e1e', fg='white')
        self.packet_log.pack(fill=tk.BOTH, expand=True)
        notebook.add(log_frame, text="Packet Analysis Log")
        
        # Vulnerability Report Tab
        vuln_frame = ttk.Frame(notebook, padding="5")
        self.vuln_text = scrolledtext.ScrolledText(vuln_frame, height=15, width=80, bg='#1e1e1e', fg='white')
        self.vuln_text.pack(fill=tk.BOTH, expand=True)
        notebook.add(vuln_frame, text="Vulnerability Report")
        
        # Statistics Tab
        stats_frame = ttk.Frame(notebook, padding="5")
        self.stats_text = scrolledtext.ScrolledText(stats_frame, height=15, width=80, bg='#1e1e1e', fg='white')
        self.stats_text.pack(fill=tk.BOTH, expand=True)
        notebook.add(stats_frame, text="Protocol Statistics")
        
        # Configure main frame grid weights
        main_frame.rowconfigure(7, weight=1)
        main_frame.columnconfigure(1, weight=1)

    def log_message(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        color_map = {
            "INFO": "white",
            "WARNING": "yellow",
            "ERROR": "red",
            "ALERT": "orange",
            "SUCCESS": "green"
        }
        
        self.packet_log.insert(tk.END, f"[{timestamp}] {level}: {message}\n")
        self.packet_log.see(tk.END)
        
        # Color coding
        if level in color_map:
            self.packet_log.tag_configure(level, foreground=color_map[level])
            self.packet_log.tag_add(level, "end-2l", "end-1l")

    def start_analysis(self):
        if self.is_analyzing:
            return
            
        try:
            target_ip = self.ip_var.get()
            port = int(self.port_var.get())
            protocol = self.protocol_var.get()
            analysis_type = self.analysis_var.get()
            
            # Validate IP address
            try:
                ipaddress.ip_address(target_ip)
            except ValueError:
                messagebox.showerror("Error", "Invalid IP address format")
                return
                
            self.is_analyzing = True
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.progress.start()
            
            self.log_message(f"Starting {analysis_type} for {protocol} on {target_ip}:{port}", "INFO")
            
            # Start analysis in separate thread
            self.capture_thread = threading.Thread(
                target=self.perform_analysis,
                args=(target_ip, port, protocol, analysis_type),
                daemon=True
            )
            self.capture_thread.start()
            
        except ValueError:
            messagebox.showerror("Error", "Invalid port number")
            self.stop_analysis()

    def stop_analysis(self):
        self.is_analyzing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress.stop()
        self.log_message("Analysis stopped", "INFO")

    def perform_analysis(self, target_ip, port, protocol, analysis_type):
        """Main analysis function running in separate thread"""
        packet_count = 0
        vulnerability_count = 0
        
        try:
            # Simulate protocol analysis (in real implementation, this would use actual packet capture)
            while self.is_analyzing and packet_count < 1000:  # Safety limit
                packet_count += 1
                
                # Simulate packet reception and analysis
                if protocol == "GTP":
                    self.analyze_gtp_packet(packet_count, target_ip)
                else:  # SCTP
                    self.analyze_sctp_packet(packet_count, target_ip)
                
                # Simulate vulnerability detection
                if packet_count % 7 == 0:  # Every 7th packet has a vulnerability
                    vulnerability_count += 1
                    self.detect_vulnerability(packet_count, protocol)
                
                # Update statistics every 10 packets
                if packet_count % 10 == 0:
                    self.update_statistics(packet_count, vulnerability_count, protocol)
                
                time.sleep(0.5)  # Simulate processing time
                
        except Exception as e:
            self.log_message(f"Analysis error: {str(e)}", "ERROR")

    def analyze_gtp_packet(self, packet_num, target_ip):
        """Analyze GTP protocol packets"""
        import random
        
        message_types = {
            1: "Echo Request",
            2: "Echo Response", 
            16: "Create PDP Context Request",
            17: "Create PDP Context Response",
            26: "Delete PDP Context Request",
            32: "Update PDP Context Request"
        }
        
        msg_type = random.choice(list(message_types.keys()))
        version = random.choice([1, 2])
        seq_num = random.randint(1, 65535)
        
        analysis_msg = f"GTPv{version} Packet #{packet_num}: {message_types[msg_type]} " \
                      f"(Seq: {seq_num}) from {target_ip}"
        
        # Simulate some suspicious patterns
        if seq_num > 60000:
            self.log_message(f"High sequence number detected: {seq_num} - Possible replay attack", "WARNING")
        
        self.log_message(analysis_msg, "INFO")

    def analyze_sctp_packet(self, packet_num, target_ip):
        """Analyze SCTP protocol packets"""
        import random
        
        chunk_type = random.choice(list(self.sctp_chunk_types.keys()))
        verification_tag = random.randint(1, 0xFFFFFFFF)
        
        analysis_msg = f"SCTP Packet #{packet_num}: {self.sctp_chunk_types[chunk_type]} " \
                      f"(Tag: {verification_tag:08x}) from {target_ip}"
        
        # Simulate vulnerability detection
        if chunk_type == 1:  # INIT chunk
            if verification_tag == 0:
                self.log_message("Zero verification tag in INIT chunk - Possible security issue", "ALERT")
        
        self.log_message(analysis_msg, "INFO")

    def detect_vulnerability(self, packet_num, protocol):
        """Simulate vulnerability detection"""
        import random
        
        vuln_type = random.choice(self.vulnerability_patterns)
        severity = random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        
        vuln_msg = f"VULNERABILITY: {vuln_type} in {protocol} packet #{packet_num} - Severity: {severity}"
        
        # Log to vulnerability tab
        self.vuln_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {vuln_msg}\n")
        self.vuln_text.see(tk.END)
        
        # Color code by severity
        color_map = {"LOW": "white", "MEDIUM": "yellow", "HIGH": "orange", "CRITICAL": "red"}
        self.vuln_text.tag_configure(severity, foreground=color_map.get(severity, "white"))
        self.vuln_text.tag_add(severity, "end-2l", "end-1l")
        
        self.log_message(vuln_msg, "ALERT")

    def update_statistics(self, packet_count, vulnerability_count, protocol):
        """Update statistics tab"""
        stats_text = f"""
Protocol Statistics for {protocol}
================================
Analysis Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Total Packets Analyzed: {packet_count}
Vulnerabilities Detected: {vulnerability_count}
Detection Rate: {(vulnerability_count/packet_count*100):.1f}%

Protocol Breakdown:
- GTP Messages: {packet_count // 2}
- SCTP Chunks: {packet_count // 2}
- Control Packets: {packet_count // 3}
- Data Packets: {packet_count * 2 // 3}

Security Assessment:
- Overall Risk Level: {'MEDIUM' if vulnerability_count > 5 else 'LOW'}
- Recommended Actions: {'Immediate review required' if vulnerability_count > 10 else 'Routine monitoring'}
"""
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, stats_text)

    def save_results(self):
        """Save analysis results to file"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if filename:
                results = {
                    "analysis_timestamp": datetime.now().isoformat(),
                    "target": f"{self.ip_var.get()}:{self.port_var.get()}",
                    "protocol": self.protocol_var.get(),
                    "analysis_type": self.analysis_var.get(),
                    "summary": {
                        "packets_analyzed": "Simulated data",
                        "vulnerabilities_found": "Simulated data",
                        "risk_level": "MEDIUM"
                    }
                }
                
                with open(filename, 'w') as f:
                    json.dump(results, f, indent=2)
                
                self.log_message(f"Results saved to {filename}", "SUCCESS")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save results: {str(e)}")

    def clear_log(self):
        """Clear all log windows"""
        self.packet_log.delete(1.0, tk.END)
        self.vuln_text.delete(1.0, tk.END)
        self.stats_text.delete(1.0, tk.END)
        self.log_message("Logs cleared", "INFO")

def main():
    root = tk.Tk()
    app = TelecomProtocolAnalyzer(root)
    root.mainloop()

if __name__ == "__main__":
    main()