
from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS
from pathlib import Path
from datetime import datetime
from collections import Counter

# Project paths
project_folder = Path(__file__).resolve().parent.parent
capture_file = project_folder / "captures" / "network_capture.pcapng"
report_file = project_folder / "reports" / "analysis_report.txt"

# Packet counters
total = 0
tcp_count = 0
udp_count = 0
dns_count = 0
ipv4_count = 0
ipv6_count = 0

# IP address counters
source_ips = Counter()
destination_ips = Counter()

# Port counters
source_ports = Counter()
destination_ports = Counter()

print("Starting Network Traffic Analysis...")

# Check capture file
if not capture_file.exists():
    raise FileNotFoundError(f"Capture file not found: {capture_file}")

# Read network packets
with PcapReader(str(capture_file)) as packets:

    for packet in packets:

        total += 1

        # IPv4 analysis
        if IP in packet:
            ipv4_count += 1

            source_ips[packet[IP].src] += 1
            destination_ips[packet[IP].dst] += 1

        # IPv6 analysis
        if IPv6 in packet:
            ipv6_count += 1

        # TCP analysis
        if TCP in packet:
            tcp_count += 1

            source_ports[packet[TCP].sport] += 1
            destination_ports[packet[TCP].dport] += 1

        # UDP analysis
        if UDP in packet:
            udp_count += 1

            source_ports[packet[UDP].sport] += 1
            destination_ports[packet[UDP].dport] += 1

        # DNS analysis
        if DNS in packet:
            dns_count += 1


# Top 10 IP addresses
top_sources = source_ips.most_common(10)
top_destinations = destination_ips.most_common(10)

ip_report = "\nTOP 10 SOURCE IP ADDRESSES:\n"

for ip, count in top_sources:
    ip_report += f"{ip}: {count} packets\n"

ip_report += "\nTOP 10 DESTINATION IP ADDRESSES:\n"

for ip, count in top_destinations:
    ip_report += f"{ip}: {count} packets\n"


# Top 10 ports
top_source_ports = source_ports.most_common(10)
top_destination_ports = destination_ports.most_common(10)

port_report = "\nTOP 10 SOURCE PORTS:\n"

for port, count in top_source_ports:
    port_report += f"Port {port}: {count} packets\n"

port_report += "\nTOP 10 DESTINATION PORTS:\n"

for port, count in top_destination_ports:
    port_report += f"Port {port}: {count} packets\n"


# Basic suspicious IP detection
suspicious_ips = []

PACKET_THRESHOLD = 100000

for ip, count in source_ips.items():

    if count > PACKET_THRESHOLD:
        suspicious_ips.append((ip, count))


# Unusual destination port analysis
COMMON_PORTS = {
    20, 21, 22, 23, 25, 53, 80, 110,
    143, 443, 445, 3306, 3389, 8080
}

unusual_ports = []

for port, count in destination_ports.items():

    if port not in COMMON_PORTS and count > 1000:
        unusual_ports.append((port, count))


# Generate suspicious IP report
security_report = "\nSUSPICIOUS TRAFFIC INDICATORS:\n"

if suspicious_ips:

    for ip, count in suspicious_ips:
        security_report += (
            f"IP: {ip} | Packets: {count} "
            "| Status: Requires investigation\n"
        )

else:
    security_report += "No IP exceeded the configured threshold.\n"


# Generate unusual port report
port_security_report = "\nUNUSUAL PORT ACTIVITY:\n"

if unusual_ports:

    for port, count in sorted(
        unusual_ports,
        key=lambda item: item[1],
        reverse=True
    )[:20]:

        port_security_report += (
            f"Port {port}: {count} packets "
            "| Status: Review required\n"
        )

else:
    port_security_report += "No unusual port activity detected.\n"


# Security findings summary
security_summary = "\nSECURITY ANALYSIS SUMMARY:\n"

security_summary += (
    f"IPs requiring review: {len(suspicious_ips)}\n"
)

security_summary += (
    f"Ports requiring review: {len(unusual_ports)}\n"
)

security_summary += (
    "Note: These are automated indicators, "
    "not confirmed attacks.\n"
)


# Generate final report
report = f"""
========================================
       NETWORK TRAFFIC ANALYSIS
========================================

Project: Network Traffic Analysis
Date: {datetime.now().strftime("%d-%m-%Y %H:%M:%S")}

PACKET STATISTICS
----------------------------------------

Total Packets: {total}

TCP Packets: {tcp_count}
UDP Packets: {udp_count}
DNS Packets: {dns_count}

IPv4 Packets: {ipv4_count}
IPv6 Packets: {ipv6_count}

{ip_report}

{port_report}

{security_report}

{port_security_report}

{security_summary}

========================================
       ANALYSIS COMPLETED
========================================
"""

# Save report
report_file.parent.mkdir(parents=True, exist_ok=True)
report_file.write_text(report, encoding="utf-8")

# Display report
print(report)

print("Report saved successfully!")
print("Location:", report_file)
