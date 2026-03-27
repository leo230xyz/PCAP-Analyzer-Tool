import tkinter as tk
from tkinter import messagebox, filedialog, LabelFrame
from functions import *
from scapy.all import rdpcap

# -------------------- THEME & CONFIG --------------------
BG_COLOR = "#1e1e1e"
FG_COLOR = "#ffffff"
BTN_COLOR = "#2d2d2d"
ACCENT = "#4cc9f0"

def browse_file():
    global packets
    file_path = filedialog.askopenfilename(
        title="Select PCAP File",
        filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")]
    )
    if file_path:
        entry.delete(0, tk.END)
        entry.insert(0, file_path)
        packets = rdpcap(file_path)
        messagebox.showinfo("Loaded", "File loaded successfully!")

def is_ready():
    """Checks if packets are loaded before running functions."""
    if 'packets' not in globals() or packets is None:
        messagebox.showwarning("No File", "Please load a PCAP file first!")
        return False
    return True

# -------------------- WRAPPER FUNCTIONS --------------------
def run_summary():
    if is_ready(): print_summary(packets); messagebox.showinfo("Done", "Summary saved!")

def run_lookup():
    if is_ready():
        ip = entry.get().strip() or None
        print_lookup_IP(packets, ip)
        messagebox.showinfo("Done", "Lookup completed!")

def run_filter_proto():
    if is_ready():
        proto = entry.get().strip().lower()
        if not proto:
            messagebox.showwarning("Input Error", "Enter protocol (tcp, udp, icmp)")
            return
        filter_proto(packets, proto)
        messagebox.showinfo("Done", "Filtering completed!")

def run_suspicious():
    if is_ready(): filter_suspicious_ports(packets); messagebox.showinfo("Done", "Audit completed!")

def run_payload_search():
    if is_ready():
        term = entry.get().strip()
        if not term:
            messagebox.showwarning("Input Error", "Enter a keyword!")
            return
        payload_search(packets, term)
        messagebox.showinfo("Done", "Search completed!")

def run_sensitive_info():
    if is_ready(): Sensitive_Info(packets); messagebox.showinfo("Done", "Leak audit completed!")

def run_dns_extract():
    if is_ready(): Extract_DNS(packets); messagebox.showinfo("Done", "DNS extracted!")

def run_identify_devices():
    if is_ready(): identify_devices(packets); messagebox.showinfo("Done", "Devices mapped!")

# -------------------- UI SETUP --------------------
root = tk.Tk()
root.title("Network Analyzer Pro")
root.geometry("550x500")
root.configure(bg=BG_COLOR)

# Title
tk.Label(root, text="NETWORK ANALYZER", font=("Impact", 24), bg=BG_COLOR, fg=ACCENT).pack(pady=10)

# Input Section
input_frame = tk.Frame(root, bg=BG_COLOR)
input_frame.pack(pady=10)
tk.Label(input_frame, text="Input (IP / Protocol / Keyword):", bg=BG_COLOR, fg=FG_COLOR).pack()
entry = tk.Entry(input_frame, width=50, bg=BTN_COLOR, fg=FG_COLOR, insertbackground="white")
entry.pack(pady=5)
tk.Button(input_frame, text="📂 Load PCAP File", command=browse_file, bg=ACCENT, fg="black", font=("Arial", 10, "bold"), width=20).pack(pady=5)

# Container for grouped buttons (Grid System)
tools_container = tk.Frame(root, bg=BG_COLOR)
tools_container.pack(pady=10, padx=20)

# --- Group 1: General Tools ---
group_gen = LabelFrame(tools_container, text=" General Analysis ", bg=BG_COLOR, fg=ACCENT, font=("Arial", 10, "bold"))
group_gen.grid(row=0, column=0, padx=10, sticky="nsew")

tk.Button(group_gen, text="📊 Print Summary", command=run_summary, width=22, bg=BTN_COLOR, fg=FG_COLOR).pack(pady=2)
tk.Button(group_gen, text="🔍 IP Lookup", command=run_lookup, width=22, bg=BTN_COLOR, fg=FG_COLOR).pack(pady=2)
tk.Button(group_gen, text="⚙ Filter Protocol", command=run_filter_proto, width=22, bg=BTN_COLOR, fg=FG_COLOR).pack(pady=2)
tk.Button(group_gen, text="🌐 Extract DNS", command=run_dns_extract, width=22, bg=BTN_COLOR, fg=FG_COLOR).pack(pady=2)

# --- Group 2: Security Tools ---
group_sec = LabelFrame(tools_container, text=" Security & Forensics ", bg=BG_COLOR, fg=ACCENT, font=("Arial", 10, "bold"))
group_sec.grid(row=0, column=1, padx=10, sticky="nsew")

tk.Button(group_sec, text="🚨 Suspicious Ports", command=run_suspicious, width=22, bg=BTN_COLOR, fg=FG_COLOR).pack(pady=2)
tk.Button(group_sec, text="🔍 Payload Search", command=run_payload_search, width=22, bg=BTN_COLOR, fg=FG_COLOR).pack(pady=2)
tk.Button(group_sec, text="🚩 Sensitive Info", command=run_sensitive_info, width=22, bg=BTN_COLOR, fg=FG_COLOR).pack(pady=2)
tk.Button(group_sec, text="📱 Identify Devices", command=run_identify_devices, width=22, bg=BTN_COLOR, fg=FG_COLOR).pack(pady=2)

# Footer Maintenance
tk.Button(root, text="🧹 Clear Results CSV", command=clear_results, bg="#ff4d4d", fg=FG_COLOR, width=30).pack(pady=20)

root.mainloop()