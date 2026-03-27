# 🛡️ Network Analyzer Tool

**Network Analyzer Tool** is a robust, Python-based desktop application for rapid network forensics, deep packet inspection (DPI), and security auditing. Built with Scapy and Tkinter, it provides an intuitive interface for security analysts to probe beyond basic packet headers and analyze the payload of network traffic.

---

## 🚀 Key Features

### Core Analysis

- **PCAP/PCAPNG Loading:** Easily load and browse capture files for in-depth analysis.
- **Packet Summarization:** Automatically generate high-level summaries of all captured traffic.
- **Protocol & IP Filtering:** Focus on specific protocols (TCP/UDP/ICMP) or drill down on activity for individual IP addresses.
- **DNS Query Extraction (New):** Instantly reveal all visited domains, helping spot potential command-and-control (C2) or malicious activity.

### Security & Forensics

- **Deep Packet Inspection (New):** Search full packet payloads for custom keywords, strings, or hex patterns.
- **Sensitive Data Audit (New):** Detect potential leaks of passwords, credentials, and session cookies in unencrypted traffic.
- **Device Fingerprinting (New):** Identify operating systems, browsers, and device types by extracting HTTP User-Agent strings.
- **Suspicious Port Detection:** Flag activity on risky ports (e.g., 21, 23, 3389, 4444) and highlight top active IPs.

---

## 🛠️ Getting Started

### Prerequisites

- **Python 3.10+**
- **Npcap** (for Windows): Required for Scapy to process capture files. [Download Npcap](https://nmap.org/npcap/)

### Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/leo230xyz/PCAP-Analyzer-Tool.git
   cd PCAP-Analyzer-Tool
   ```

2. **Install Dependencies**
   ```bash
   pip install scapy
   ```

3. **Run the Application**
   ```bash
   python main.py
   ```

---

## 📖 Usage

- The interface is organized into two main zones:
  - **General Analysis:** Network mapping, DNS extraction, and IP tracking.
  - **Security & Forensics:** Deep inspection, device identification, leak detection.
- **Inputs:** For "Lookup IP," "Filter Protocol," or "Payload Search," enter your term or IP, then click the corresponding button.
- **Results:** Realtime logs are saved to `results.csv` in the project folder—ready for use with Excel or Power BI.

---

## 📊 Technical Details

- **Backend:** Scapy (packet parsing and manipulation)
- **Frontend:** Tkinter (custom dark-themed grid GUI)
- **Storage:** CSV-based logging; use "Clear Results" to refresh logs as needed

---

## 🤝 Contributing

Contributions are welcome! Suggest new security filters, payload parsers, or other features by forking the repo and submitting a pull request.

---

## 📜 License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
