
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
│
├── screenshots/
│
├── src/
│   ├── traffic_analysis.py
│   └── traffic_dashboard.py
│
├── reports/
│   ├── analysis_report.txt
│   ├── protocol_analysis.png
│   ├── ip_analysis.png
│   └── Network_Traffic_Analysis_Final_Report.pdf
│
├── .gitignore
├── requirements.txt
└── README.md
```

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Shubhgu-coder/Network-Traffic-Analysis.git
```

### 2. Move into the Project Folder

```bash
cd Network-Traffic-Analysis
```

### 3. Install Dependencies

```bash
python -m pip install -r requirements.txt
```

## How to Run

### Step 1: Prepare the Capture File

Place an authorized PCAP or PCAPNG capture file inside the `captures` folder.

### Step 2: Run Traffic Analysis

```bash
python src/traffic_analysis.py
```

### Step 3: Generate Traffic Visualizations

```bash
python src/traffic_dashboard.py
```

The generated reports and visualizations are saved in the `reports` folder.

## Analysis Performed

The project performs the following analysis:

- Total packet count
- TCP and UDP traffic analysis
- DNS packet analysis
- IPv4 and IPv6 analysis
- Top 10 source IP addresses
- Top 10 destination IP addresses
- Top source and destination ports
- Basic suspicious IP indicators
- Unusual destination port activity

## Security Analysis

The project uses basic threshold-based indicators to identify IP addresses and destination ports that may require further investigation.

These indicators do not confirm malicious activity. High packet counts or uncommon ports can also occur during normal network communication.

Further investigation is necessary before classifying any traffic as suspicious or malicious.

## Reports and Visualizations

The project generates:

- Text-based network traffic analysis report.
- Protocol analysis visualization.
- IP address analysis visualization.
- Final project documentation in PDF format.

## Security and Privacy Note

- Analyze only network traffic that you own or have permission to inspect.
- Packet captures may contain sensitive network information.
- Do not upload private or sensitive PCAP files to a public repository.
- Review files before publishing them on GitHub.

## Limitations and Future Improvements

- Improve suspicious traffic detection using time-based analysis.
- Add TCP connection tracking.
- Improve anomaly detection techniques.
- Add more protocol analysis features.
- Generate additional traffic visualizations.

## Disclaimer

This project is developed for educational and cybersecurity learning purposes as part of a virtual internship.

The analysis results are intended for learning and basic network investigation. They should not be treated as confirmed security alerts.

## Author

**Shubham Gupta**

Cybersecurity Virtual Internship Project
