# PCAP Generator – Synthetic Network Traffic Builder

### Overview
**PCAP Generator** is a Python application that safely creates **synthetic packet capture (PCAP) files** containing realistic network traffic.  
It simulates a mix of **benign** and **suspicious** activities, such as web browsing, DNS, ICMP pings, ARP requests, and simulated attack patterns (SYN probes, ping sweeps, brute-force attempts, beaconing, and data exfil), while ensuring that all payloads remain completely **non-harmful and clearly labeled**.

The tool is designed for **SOC analysts, cybersecurity students, and educators** who need reproducible, diverse traffic samples for:
- SIEM testing and correlation rule validation
- Detection engineering and threat-hunting exercises
- Blue team or digital forensics training labs

---

## Features
- Generates realistic-looking packets using [Scapy](https://scapy.net/)
- Includes:
  - TCP, UDP, ICMP, ARP, DNS, and DHCP benign traffic
  - Simulated “malicious” patterns: SYN scans, ping sweeps, brute-force attempts, beaconing, and exfiltration (non-actionable)
- Automatically writes packets to a `.pcap` file
- Logs generation progress every 100 packets
- Loops continuously up to 10,000 packets or until interrupted
- Safe for offline environments and training use; **no live traffic sent**

---

## Example Output
- Typical protocols observed: ARP, DNS, HTTP, ICMP, DHCP, UDP, TCP
- Simulated attack labels visible in payloads:
