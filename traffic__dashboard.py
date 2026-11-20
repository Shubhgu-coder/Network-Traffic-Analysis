
import matplotlib.pyplot as plt

# Traffic analysis results
protocols = ["TCP", "UDP", "DNS"]
protocol_counts = [2643027, 1074957, 4167]

ip_versions = ["IPv4", "IPv6"]
ip_counts = [2520531, 230730]

# Protocol traffic chart
plt.figure(figsize=(8, 5))
plt.bar(protocols, protocol_counts)
plt.title("Network Protocol Traffic Analysis")
plt.xlabel("Protocol")
plt.ylabel("Number of Packets")
plt.tight_layout()
plt.savefig("../reports/protocol_analysis.png")
plt.show()

# IP version chart
plt.figure(figsize=(8, 5))
plt.bar(ip_versions, ip_counts)
plt.title("IPv4 vs IPv6 Traffic Analysis")
plt.xlabel("IP Version")
plt.ylabel("Number of Packets")
plt.tight_layout()
plt.savefig("../reports/ip_analysis.png")
plt.show()

print("Dashboard charts generated successfully!")
