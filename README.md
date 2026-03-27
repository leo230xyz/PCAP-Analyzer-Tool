🛡️ Network Analyzer Pro
A powerful, desktop-based Python application designed for rapid Network Forensics, Deep Packet Inspection (DPI), and Security Auditing. Built with Scapy and Tkinter, this tool provides a specialized interface for security analysts to move beyond basic headers and into the payload of network traffic.

🚀 Key Features
Core Analysis
PCAP/PCAPNG Loading: Seamlessly browse and ingest capture files for analysis.

Packet Summarization: Generate a high-level overview of all traffic in the capture.

Protocol & IP Filtering: Isolate specific traffic (TCP/UDP/ICMP) or track behavior for a single IP.

DNS Query Extraction: (New) Automatically maps all domain names visited within the capture to identify potential C2 (Command & Control) or malicious site access.

Security & Forensics
Deep Packet Inspection (DPI): (New) Search entire packet payloads for specific keywords, strings, or hex patterns.

Sensitive Data Audit: (New) Scans unencrypted traffic for potential leaks of passwords, login credentials, and session cookies.

Device Fingerprinting: (New) Identifies hardware and software on the network (OS, Browsers, Device Types) by extracting HTTP User-Agent strings.

Suspicious Port Detection: Flags activity on high-risk ports (e.g., 21, 23, 3389, 4444) and ranks the most active involved IPs.

🛠️ Getting Started
Prerequisites
Python 3.10+

Npcap (for Windows): Required by Scapy to read network files correctly. Download here.

Installation
Clone the repository:

Bash
git clone https://github.com/leo230xyz/PCAP-Analyzer-Tool.git
cd PCAP-Analyzer-Tool
Install dependencies:

Bash
pip install scapy
Run the application:

Bash
python main.py
📖 Usage
The interface is divided into two primary logical zones:

General Analysis: Use these for standard network mapping, DNS extraction, and IP tracking.

Security & Forensics: Use these for deeper inspection, identifying connected devices, and searching for data leaks.

Inputs: For "Lookup IP," "Filter Protocol," or "Payload Search," enter your keyword/IP into the text box before clicking the tool button.

Results: All analysis is logged in real-time. Open results.csv in the project directory to view your structured data for use in Excel or PowerBI.

📊 Technical Details
Backend: Scapy (Packet manipulation and Layer 7 parsing)

Frontend: Tkinter (Custom dark-themed, categorized Grid GUI)

Storage: CSV-based logging with result appending and "Clear Results" maintenance.

🤝 Contributing
Contributions are welcome! If you have suggestions for new security filters or payload decryption methods, feel free to fork the repo and submit a pull request.

📜 License
Distributed under the MIT License. See LICENSE for more information.
