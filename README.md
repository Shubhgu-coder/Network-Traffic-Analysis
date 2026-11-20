
# Network Traffic Analysis

## Project Overview

Network Traffic Analysis is a Python-based cybersecurity project that analyzes captured network packets using Scapy and visualizes traffic statistics using Matplotlib.

The project helps identify network protocols, frequently communicating IP addresses, commonly used ports, and basic traffic indicators that may require further investigation.

## Objectives

- Analyze captured network traffic.
- Identify TCP, UDP, DNS, IPv4 and IPv6 packets.
- Find the top source and destination IP addresses.
- Identify frequently used source and destination ports.
- Generate basic suspicious traffic indicators.
- Visualize network traffic statistics.

## Technologies Used

- Python
- Scapy
- Matplotlib
- Wireshark

## Project Features

1. Packet analysis
2. Protocol identification
3. Source and destination IP analysis
4. Port activity analysis
5. Basic suspicious IP detection
6. Unusual destination port identification
7. Traffic visualization
8. Automated text report generation

## Project Structure

```text
Network-Traffic-Analysis/
│
├── captures/
├── screenshots/
├── src/
│   ├── traffic_analysis.py
│   └── traffic_dashboard.py
│
├── reports/
│   ├── analysis_report.txt
│   ├── protocol_analysis.png
│   └── ip_analysis.png
│
├── requirements.txt
└── README.md
```

## Installation

Clone the repository:

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

Move into the project folder:

```bash
cd Network-Traffic-Analysis
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## How to Run

Place your authorized PCAP or PCAPNG capture file inside the `captures` folder.

Run the traffic analysis script:

```bash
python src/traffic_analysis.py
```

Run the dashboard script:

```bash
python src/traffic_dashboard.py
```

The generated reports and visualizations are saved in the `reports` folder.

## Security Note

The suspicious IP and unusual port detection features use basic threshold-based indicators.

These indicators do not confirm malicious activity. Further investigation is required before classifying any traffic as an attack.

## Disclaimer

This project is developed for educational and cybersecurity learning purposes.

Only analyze network traffic that you own or have permission to inspect.

## Author

Cybersecurity Virtual Internship Project
