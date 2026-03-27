Network Analyzer Tool
A lightweight, desktop-based Python application designed for rapid PCAP (Packet Capture) analysis and security auditing. Built with Scapy and Tkinter, this tool allows network administrators and security enthusiasts to filter traffic, lookup specific IP behavior, and identify suspicious port activity through an intuitive GUI.

🚀 Features
PCAP/PCAPNG Loading: Easily browse and load capture files from your local system.

Packet Summarization: Generate a complete high-level overview of all traffic in the capture.

IP Address Lookup: Filter all traffic associated with a specific Source or Destination IP.

Protocol Filtering: Quickly isolate TCP, UDP, or ICMP traffic for targeted analysis.

Suspicious Port Detection: Automatically identifies traffic on high-risk ports (e.g., 21, 22, 23, 3389, 4444) and ranks the most active involved IPs.

CSV Export: All analysis results are automatically saved to a structured results.csv for use in Excel, PowerBI, or other reporting tools.

🛠️ Getting Started
Prerequisites
Python 3.10+

Npcap (for Windows): Required by Scapy to read network files correctly. Download here.

Installation
Clone the repository:

Bash
git clone https://github.com/YOUR_USERNAME/Network-Analyzer-Tool.git
cd Network-Analyzer-Tool
Install dependencies:

Bash
pip install scapy
Run the application:

Bash
python main.py
📖 Usage
Browse File: Select your .pcap or .pcapng file.

Analysis: Choose from the available analysis buttons.

Inputs: For "Lookup IP" or "Filter Protocol," enter the relevant IP or protocol (tcp/udp) into the text box before clicking the button.

Results: Check the console for real-time "Done!!" messages and open results.csv in the project directory for the full dataset.

📊 Technical Details
Backend: Scapy (Packet manipulation and parsing)

Frontend: Tkinter (Custom dark-themed GUI)

Storage: CSV-based logging with result appending

🤝 Contributing
Contributions are welcome! If you have suggestions for new security filters or data visualizations, feel free to fork the repo and submit a pull request.

📜 License
Distributed under the MIT License. See LICENSE for more information.