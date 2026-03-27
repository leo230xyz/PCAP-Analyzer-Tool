import os
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS
from scapy.all import Raw

# Helper: Extract basic packet metadata
def get_packet_info(packet):
    proto_field = packet[IP].get_field("proto")
    return {
        "src": packet[IP].src,
        "dst": packet[IP].dst,
        "proto": proto_field.i2repr(packet[IP], packet[IP].proto)
    }

# Feature: Full CSV Summary
def print_summary(packets): 
    print("Processing summary...")
    with open("./results.csv", "a+") as file:
        for packet in packets:
            # Replaced commas to ensure CSV columns stay aligned
            clean_summary = str(packet.summary()).replace(",", " ")
            file.write(f"summary,{clean_summary}\n")
        file.write(f"Total Packets,{len(packets)}\n\n")
    print("Done!!")

# Feature: IP Specific Lookup
def print_lookup_IP(packets, ip=None):
    match_count = 0
    print(f"Looking up IP: {ip if ip else 'All'}...")
    with open("./results.csv", "a+") as file:
        for packet in packets:
            if packet.haslayer(IP):
                info = get_packet_info(packet)
                if ip is None or ip in (info['src'], info['dst']):
                    match_count += 1
                    file.write(f"lookup,{info['src']},{info['dst']},{info['proto']}\n")
        file.write(f"Total Packets For {ip if ip else 'All'},{match_count}\n\n")
    print("Done!!")

# Feature: Protocol Filtering
def filter_proto(packets, user_proto):
    match_count = 0
    user_proto = user_proto.lower()
    print(f"Filtering for: {user_proto}...")
    with open("./results.csv", "a+") as file:
        for packet in packets:
            if packet.haslayer(IP):
                info = get_packet_info(packet)
                if info['proto'].lower() == user_proto:
                    file.write(f"filter,{info['src']},{info['dst']},{info['proto']}\n")
                    match_count += 1
        file.write(f"Total Packets for {user_proto},{match_count}\n\n")
    print("Done!!")

# Feature: Suspicious Port Audit
def filter_suspicious_ports(packets):
    suspicious_ports = [21, 22, 23, 25, 53, 80, 443, 3389, 4444]
    ip_counter = {}
    print("Analyzing suspicious ports...")
    for packet in packets:
        if not packet.haslayer(IP): continue
        layer = packet[TCP] if packet.haslayer(TCP) else packet[UDP] if packet.haslayer(UDP) else None
        if layer and (layer.sport in suspicious_ports or layer.dport in suspicious_ports):
            info = get_packet_info(packet)
            ip_counter[info["src"]] = ip_counter.get(info["src"], 0) + 1
            ip_counter[info["dst"]] = ip_counter.get(info["dst"], 0) + 1

    with open("./results.csv", "a+") as file:
        for ip, count in sorted(ip_counter.items(), key=lambda x: x[1], reverse=True):
            file.write(f"suspicious,{ip},{count}\n")
        file.write(f"Total Suspicious Events,{sum(ip_counter.values())}\n\n")
    print("Done!!")

# Feature: DPI Keyword Search
def payload_search(packets, search_term):
    match_count = 0
    term = search_term.lower()
    print(f"DPI Search for: '{term}'...")
    with open("./results.csv", "a+") as file:
        for packet in packets:
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()
                if term in payload:
                    info = get_packet_info(packet)
                    file.write(f"payload_match,{info['src']},{info['dst']},{term}\n")
                    match_count += 1
        file.write(f"Total Matches for {term},{match_count}\n\n")
    print("Done!!")

# Feature: Sensitive Information Leak Audit
def Sensitive_Info(packets):
    match_count = 0
    keywords = ["password", "login", "admin", "cookie", "session", "user", "pass"]
    print("🚩 Auditing for leaks...")
    with open("./results.csv", "a+") as file:
        for packet in packets:
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()
                found = next((word for word in keywords if word in payload), None)
                if found:
                    info = get_packet_info(packet)
                    file.write(f"sensitive_leak,{info['src']},{info['dst']},{found}\n")
                    match_count += 1
        file.write(f"Total Sensitive Leaks,{match_count}\n\n")
    print(f"Done!! Found {match_count} leaks.")

# Feature: Domain Name Extraction
def Extract_DNS(packets):
    print("Extracting DNS...")
    queries = set()
    for packet in packets:
        if packet.haslayer(DNS) and packet.getlayer(DNS).qd:
            domain = packet.getlayer(DNS).qd.qname.decode('utf-8', errors='ignore').strip('.')
            queries.add(domain)
    with open("./results.csv", "a+") as file:
        for q in queries:
            file.write(f"dns_query,{q}\n")
        file.write(f"Total Unique Domains,{len(queries)}\n\n")
    print("Done!!")

# Feature: Device Fingerprinting (User-Agents)
def identify_devices(packets):
    print("Identifying devices...")
    inventory = {}
    marker = "user-agent:"
    with open("./results.csv", "a+") as file:
        for packet in packets:
            if packet.haslayer(IP) and packet.haslayer(Raw):
                src_ip = packet[IP].src
                if src_ip in inventory: continue
                payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()
                if marker in payload:
                    try:
                        agent = payload.split(marker)[1].split("\r\n")[0].strip().replace(",", " ")
                        inventory[src_ip] = agent
                        file.write(f"device_discovery,{src_ip},{agent}\n")
                    except IndexError: continue
        file.write(f"Total Unique Devices,{len(inventory)}\n\n")
    print("Done!!")

# Maintenance: Reset CSV
def clear_results():
    if os.path.exists("./results.csv"):
        with open("./results.csv", "w") as file: pass
    print("Logs cleared!")