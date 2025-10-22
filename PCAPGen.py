#!/usr/bin/env python3
"""
synthetic_pcap_generator.py

Safe PCAP generator for defensive/educational use.

- Generates benign traffic (ARP, DHCP, DNS, ICMP, TCP, UDP) including unicast/multicast/broadcast.
- Injects SIMULATED suspicious patterns (SYN probes, ping sweep, repeated "brute" attempts, beaconing, simulated exfil)
  using harmless placeholder payloads (SIMULATED_*). These are intentionally non-actionable.
- Writes packets to a PCAP file using Scapy's PcapWriter (offline only).
- Logs progress to console every LOG_EVERY packets and stops at MAX_PACKETS or on Ctrl+C.

USAGE:
  - Ensure scapy is installed: pip install scapy
  - python3 synthetic_pcap_generator.py
"""

import random
import time
import signal
import sys
from scapy.all import (
    Ether,
    IP,
    IPv6,
    UDP,
    TCP,
    ICMP,
    ARP,
    BOOTP,
    DHCP,
    DNS,
    DNSQR,
    DNSRR,
    sendp,
    PcapWriter,
)

# -----------------------
# Config
# -----------------------
OUTPUT_PCAP = "synthetic_traffic_safe.pcap"
LOG_EVERY = 100
MAX_PACKETS = 10000
RANDOM_SEED = 42
INTER_PACKET_SLEEP = 0.0  # no real sending; adjust to simulate time gaps (seconds)
# -----------------------

random.seed(RANDOM_SEED)

# Helper utilities
def rand_mac():
    # Locally administered MAC (02:xx:xx:xx:xx:xx)
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0x00, 0xFF) for _ in range(5))

def rand_private_ipv4():
    # choose a private range
    block = random.choice([10, 172, 192])
    if block == 10:
        return "10.%d.%d.%d" % (random.randint(0, 255), random.randint(1, 254), random.randint(1, 254))
    elif block == 172:
        return "172.%d.%d.%d" % (random.randint(16, 31), random.randint(1, 254), random.randint(1, 254))
    else:
        return "192.168.%d.%d" % (random.randint(0, 255), random.randint(1, 254))

def rand_port(low=1024, high=65535):
    return random.randint(low, high)

def make_eth_ip_udp(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, payload=b""):
    eth = Ether(src=src_mac, dst=dst_mac)
    ip = IP(src=src_ip, dst=dst_ip)
    udp = UDP(sport=src_port, dport=dst_port)
    return eth / ip / udp / payload

def make_eth_ip_tcp(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, flags="S", payload=b""):
    eth = Ether(src=src_mac, dst=dst_mac)
    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(sport=src_port, dport=dst_port, flags=flags, seq=random.randint(0, (1 << 32) - 1))
    return eth / ip / tcp / payload

def make_icmp_echo(src_mac, dst_mac, src_ip, dst_ip, id=None, seq=1, payload=b""):
    eth = Ether(src=src_mac, dst=dst_mac)
    ip = IP(src=src_ip, dst=dst_ip)
    icmp = ICMP(type=8, id=(id or random.randint(0, 65535)), seq=seq)
    return eth / ip / icmp / payload

def make_arp_request(src_mac, src_ip, target_ip):
    eth = Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac)
    arp = ARP(op=1, hwsrc=src_mac, psrc=src_ip, pdst=target_ip)
    return eth / arp

def make_arp_reply(src_mac, dst_mac, src_ip, dst_ip):
    eth = Ether(dst=dst_mac, src=src_mac)
    arp = ARP(op=2, hwsrc=src_mac, psrc=src_ip, hwdst=dst_mac, pdst=dst_ip)
    return eth / arp

def make_dns_query(src_mac, dst_mac, src_ip, dst_ip, qname="example.local"):
    eth = Ether(src=src_mac, dst=dst_mac)
    ip = IP(src=src_ip, dst=dst_ip)
    udp = UDP(sport=rand_port(), dport=53)
    dns = DNS(qr=0, qd=DNSQR(qname=qname))
    return eth / ip / udp / dns

def make_dns_response(query_pkt, answer_ip):
    # build a simple DNS response to match the query
    eth = Ether(src=query_pkt[Ether].dst, dst=query_pkt[Ether].src)
    ip = IP(src=query_pkt[IP].dst, dst=query_pkt[IP].src)
    udp = UDP(sport=53, dport=query_pkt[UDP].sport)
    qname = query_pkt[DNS].qd.qname
    dns = DNS(qr=1, qd=query_pkt[DNS].qd, an=DNSRR(rrname=qname, rdata=answer_ip), id=random.randint(0, 65535))
    return eth / ip / udp / dns

def make_dhcp_discover(client_hw=None, src_ip="0.0.0.0"):
    """
    Build a simplified DHCP Discover packet for PCAP generation.
    - client_hw: client MAC string like "02:aa:bb:cc:dd:ee". If None, a random MAC is generated.
    - src_ip: source IP for the outer IP header (usually 0.0.0.0 for DHCP DISCOVER).
    Returns a Scapy packet (Ether / IP / UDP / BOOTP / DHCP).
    """
    client_hw = client_hw or rand_mac()
    # convert MAC string to raw bytes for BOOTP chaddr (pad/truncate to 16 bytes)
    mac_bytes = bytes.fromhex(client_hw.replace(":", ""))
    if len(mac_bytes) < 16:
        mac_bytes = mac_bytes + b"\x00" * (16 - len(mac_bytes))
    else:
        mac_bytes = mac_bytes[:16]

    eth = Ether(dst="ff:ff:ff:ff:ff:ff", src=client_hw)
    ip = IP(src=src_ip, dst="255.255.255.255")
    udp = UDP(sport=68, dport=67)
    # BOOTP with a random transaction ID
    bootp = BOOTP(op=1, chaddr=mac_bytes, xid=random.randint(1, 0xFFFFFFFF))
    # DHCP Discover option (simplified)
    dhcp = DHCP(options=[("message-type", "discover"), "end"])
    return eth / ip / udp / bootp / dhcp


def make_dhcp_offer(client_hw, yiaddr="192.168.10.100"):
    eth = Ether(dst=client_hw, src=rand_mac())
    ip = IP(src="192.168.10.1", dst="255.255.255.255")
    udp = UDP(sport=67, dport=68)
    bootp = BOOTP(op=2, chaddr=bytes.fromhex(client_hw.replace(":", "")), yiaddr=yiaddr, xid=random.randint(1, 0xFFFFFFFF))
    dhcp = DHCP(options=[("message-type", "offer"), ("server_id", "192.168.10.1"), "end"])
    return eth / ip / udp / bootp / dhcp

# Simulated "malicious" payload markers (non-actionable)
SIM_PL_SYN = b"SIMULATED_SYN_PROBE"
SIM_PL_PING = b"SIMULATED_PING_SWEEP"
SIM_PL_BRUTE = b"SIMULATED_BRUTE_ATTEMPT"
SIM_PL_BEACON = b"SIMULATED_BEACON"
SIM_PL_EXFIL = b"SIMULATED_EXFIL_PAYLOAD"

# Prepare PCAP writer
pcap = PcapWriter(OUTPUT_PCAP, append=False, sync=True)
packet_count = 0
running = True

def signal_handler(sig, frame):
    global running
    print("\nReceived interrupt, finishing and closing pcap.")
    running = False

signal.signal(signal.SIGINT, signal_handler)

# Generate a small set of anchored devices to make traffic look coherent
devices = []
for i in range(8):
    mac = rand_mac()
    ip = rand_private_ipv4()
    devices.append({"mac": mac, "ip": ip, "name": f"host{i}"})

# A few special IPs for "external" servers (still private ranges)
external_servers = [
    {"mac": rand_mac(), "ip": "192.168.200.10", "role": "web"},
    {"mac": rand_mac(), "ip": "192.168.200.20", "role": "dns"},
    {"mac": rand_mac(), "ip": "192.168.200.30", "role": "fileserver"},
]

# Helper to pick random internal device
def pick_device():
    return random.choice(devices)

# Packet generation patterns
def generate_benign_packet():
    choice = random.choices(
        ["arp", "dns_query_resp", "dhcp", "icmp", "tcp_flow", "udp_flow", "multicast"],
        weights=[5, 15, 3, 10, 30, 25, 2],
        k=1
    )[0]
    if choice == "arp":
        if random.random() < 0.6:
            d = pick_device()
            target_ip = pick_device()["ip"]
            pkt = make_arp_request(d["mac"], d["ip"], target_ip)
        else:
            src = pick_device()
            dst = pick_device()
            pkt = make_arp_reply(src["mac"], dst["mac"], src["ip"], dst["ip"])
        label = "ARP"
    elif choice == "dns_query_resp":
        client = pick_device()
        server = random.choice(external_servers)
        qname = random.choice(["example.local", "updates.corp", "service.internal", "cdn.example.com"])
        q = make_dns_query(client["mac"], server["mac"], client["ip"], server["ip"], qname=qname)
        # follow with a plausible response (write both)
        r = make_dns_response(q, answer_ip=server["ip"])
        pcap.write(q); pcap.write(r)
        return ("DNS", q)  # already written two packets
    elif choice == "dhcp":
        client = pick_device()
        discover = make_dhcp_discover(client_hw=client["mac"])
        offer = make_dhcp_offer(client_hw=client["mac"])
        pcap.write(discover); pcap.write(offer)
        return ("DHCP", discover)
    elif choice == "icmp":
        src = pick_device()
        dst = pick_device()
        pkt = make_icmp_echo(src["mac"], dst["mac"], src["ip"], dst["ip"], payload=b"hello")
        label = "ICMP_ECHO"
    elif choice == "tcp_flow":
        src = pick_device()
        dst = random.choice(external_servers)
        sport = rand_port()
        dport = random.choice([80, 443, 8080, 22, 3306])
        # simple handshake style: SYN, SYN/ACK, ACK, data, FIN
        syn = make_eth_ip_tcp(src["mac"], dst["mac"], src["ip"], dst["ip"], sport, dport, flags="S")
        synack = make_eth_ip_tcp(dst["mac"], src["mac"], dst["ip"], src["ip"], dport, sport, flags="SA")
        ack = make_eth_ip_tcp(src["mac"], dst["mac"], src["ip"], dst["ip"], sport, dport, flags="A", payload=b"")
        data = make_eth_ip_tcp(src["mac"], dst["mac"], src["ip"], dst["ip"], sport, dport, flags="PA", payload=b"GET /index.html HTTP/1.1\r\nHost: example\r\n\r\n")
        fin = make_eth_ip_tcp(src["mac"], dst["mac"], src["ip"], dst["ip"], sport, dport, flags="FA")
        pcap.write(syn); pcap.write(synack); pcap.write(ack); pcap.write(data); pcap.write(fin)
        return ("TCP_FLOW", syn)
    elif choice == "udp_flow":
        src = pick_device()
        dst = random.choice(external_servers)
        sport = rand_port()
        dport = random.choice([53, 123, 5060, 5000])
        payload = b"Sample UDP payload"
        pkt = make_eth_ip_udp(src["mac"], dst["mac"], src["ip"], dst["ip"], sport, dport, payload=payload)
        label = f"UDP:{dport}"
    elif choice == "multicast":
        src = pick_device()
        dst_mac = "01:00:5e:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
        dst_ip = "224.%d.%d.%d" % (random.randint(0, 255), random.randint(0, 255), random.randint(1, 254))
        pkt = make_eth_ip_udp(src["mac"], dst_mac, src["ip"], dst_ip, rand_port(), rand_port(), payload=b"multicast data")
        label = "MULTICAST"
    else:
        pkt = None
        label = "UNKNOWN"

    return (label, pkt)

def generate_simulated_suspicious(pattern_id):
    """
    Patterns:
    1 - SYN probe (single SYN packets)
    2 - Ping sweep (multiple ICMP echo requests to several targets)
    3 - Brute-force style repeated TCP attempts (small repeated payloads)
    4 - Beaconing UDP
    5 - Simulated exfil (small TCP session with labeled payload)
    """
    if pattern_id == 1:
        src = pick_device()
        dst = pick_device()
        pkt = make_eth_ip_tcp(src["mac"], dst["mac"], src["ip"], dst["ip"], rand_port(), random.choice([22, 80, 443, 3306]), flags="S", payload=SIM_PL_SYN)
        return ("SIM_SYN_PROBE", pkt)
    elif pattern_id == 2:
        base = pick_device()
        pkts = []
        for i in range(5):  # small sweep
            target_ip = rand_private_ipv4()
            pkt = make_icmp_echo(base["mac"], rand_mac(), base["ip"], target_ip, payload=SIM_PL_PING)
            pkts.append(pkt)
        # write all sweep packets
        for p in pkts:
            pcap.write(p)
        return ("SIM_PING_SWEEP", pkts[0])
    elif pattern_id == 3:
        src = pick_device()
        dst = pick_device()
        pkts = []
        sport = rand_port()
        dport = random.choice([22, 21, 23, 3389])
        for attempt in range(4):
            pkt = make_eth_ip_tcp(src["mac"], dst["mac"], src["ip"], dst["ip"], sport + attempt, dport, flags="S", payload=SIM_PL_BRUTE)
            pkts.append(pkt)
        for p in pkts:
            pcap.write(p)
        return ("SIM_BRUTE_REPEAT", pkts[0])
    elif pattern_id == 4:
        # beaconing UDP: periodic small packets from one host to an "external" beacon server
        src = pick_device()
        dst = random.choice(external_servers)
        pkt = make_eth_ip_udp(src["mac"], dst["mac"], src["ip"], dst["ip"], rand_port(), 9999, payload=SIM_PL_BEACON)
        return ("SIM_BEACON", pkt)
    elif pattern_id == 5:
        src = pick_device()
        dst = random.choice(external_servers)
        sport = rand_port()
        dport = 443
        syn = make_eth_ip_tcp(src["mac"], dst["mac"], src["ip"], dst["ip"], sport, dport, flags="S")
        synack = make_eth_ip_tcp(dst["mac"], src["mac"], dst["ip"], src["ip"], dport, sport, flags="SA")
        data = make_eth_ip_tcp(src["mac"], dst["mac"], src["ip"], dst["ip"], sport, dport, flags="PA", payload=b"SIMULATED_EXFIL_PAYLOAD: harmless sample data")
        pcap.write(syn); pcap.write(synack); pcap.write(data)
        return ("SIM_EXFIL", data)
    else:
        return ("SIM_UNKNOWN", None)

# Main generator loop
try:
    last_log_time = time.time()
    while running and packet_count < MAX_PACKETS:
        # bias: more benign than simulated suspicious
        if random.random() < 0.85:
            lbl, pkt = generate_benign_packet()
            # Some generator helper functions write multiple packets already and returned early
            if pkt is None:
                # if we got a tuple with already-written packets returned
                # handle gracefully
                packet_count += 1
            else:
                pcap.write(pkt)
                packet_count += 1
                last_pkt = pkt
                last_label = lbl
        else:
            pat = random.choice([1,2,3,4,5])
            lbl, pkt = generate_simulated_suspicious(pat)
            # some patterns pre-write series to pcap and return representative pkt
            if isinstance(pkt, list):
                packet_count += len(pkt)
            elif pkt is None:
                packet_count += 1
            else:
                pcap.write(pkt)
                packet_count += 1
            last_pkt = pkt
            last_label = lbl

        # Periodic logging
        if packet_count % LOG_EVERY == 0:
            try:
                if last_pkt is not None:
                    if last_pkt.haslayer(IP):
                        sip = last_pkt[IP].src
                        dip = last_pkt[IP].dst
                    else:
                        sip = "N/A"; dip = "N/A"
                else:
                    sip = dip = "N/A"
            except Exception:
                sip = dip = "N/A"
            print(f"[{packet_count}] Last: {last_label} {sip} -> {dip}")

        # optional realistic pacing
        if INTER_PACKET_SLEEP > 0:
            time.sleep(INTER_PACKET_SLEEP)

    print(f"Finished: wrote up to {packet_count} packets into {OUTPUT_PCAP}")

except KeyboardInterrupt:
    print("\nUser interrupted. Closing pcap.")
finally:
    pcap.close()
