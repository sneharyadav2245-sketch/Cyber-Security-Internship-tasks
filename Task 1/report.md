
## 📌 Task 1: Network Scanning and Traffic Capture
Date: 04 August, 2025

This task required us to perform **network scanning and traffic capture** in a simulated environment to identify open ports, analyze services, and capture relevant network traffic using tools of our choice.

### ✅ Tools & Techniques Used
- **Nmap** for port scanning (`-sS -sV -A -T3`)
- **Wireshark** for packet capture and protocol analysis
- **Linux Terminal** for command execution and scripting
- **Screenshotting and pcap analysis** to document findings

---

## 📊 Description of Key Files

| File Name               | Description |
|------------------------|-------------|
| `LocalScan.nmap`       | Human-readable summary of Nmap scan results |
| `LocalScan.xml`        | Machine-parsable scan results (XML format) |
| `LocalScan.gnmap`      | Greppable Nmap output for script processing |
| `Capture.txt`          | Notes or output logs from the scanning session |
| `scan.png`             | Visual evidence of the scan (e.g., Nmap terminal or result) |
| `WholeTraffic.pcapng`  | Complete network capture (can include all protocols) |
| `dnsCapture.pcapng`    | Targeted capture showing DNS queries and responses |

---

## 🎯 Objective & Approach

- **Objective**: Identify all open ports and active services on a local test machine.
- **Approach**:
  1. Scanned the target using Nmap SYN and service version detection.
  2. Captured all network traffic using Wireshark during scanning.
  3. Filtered and analyzed DNS traffic separately.
  4. Saved the raw scan output and supporting files as evidence.

---
## 🔎 Open Port Identified

- **Port**: 53/tcp  
- **Service**: domain  
- **Service Version**: dnsmasq 2.90  
- **OS**: Linux 2.6.X

---

## 🧠 1. Common Service on Port 53

| Attribute        | Value                                      |
|------------------|--------------------------------------------|
| **Port**         | 53 (TCP/UDP)                               |
| **Typical Service** | DNS (Domain Name System)                |
| **Software Found** | dnsmasq v2.90                            |
| **Usage**        | Resolves domain names to IP addresses (e.g., `google.com → 142.250.64.78`) |

`dnsmasq` is a lightweight DNS forwarder and DHCP server commonly used in embedded devices, small networks, or home routers.

---

## ⚠️ 2. Potential Security Risks of Port 53 (DNS)

| Risk Category                    | Description |
|----------------------------------|-------------|
| **1. DNS Amplification DDoS**    | If misconfigured, attackers can send spoofed requests to use the server as part of a large-scale amplification attack. |
| **2. DNS Spoofing / Poisoning**  | If not secured (e.g., no DNSSEC), it can be tricked into providing malicious IP addresses. |
| **3. Information Disclosure**    | May leak internal or sensitive network information if zone transfers (`AXFR`) are allowed. |
| **4. Unauthorized Recursive Queries** | Open resolvers can be abused by external clients if not properly firewalled. |
| **5. Older Version Exploits**    | `dnsmasq` v2.90 may be vulnerable if security patches are not applied (e.g., CVE-2020-25681 to CVE-2020-25687). |

---

## 🔐 3. Mitigation Tips

| Action              | Description |
|---------------------|-------------|
| 🔒 **Restrict Access**    | Use firewalls (`iptables`, `ufw`) to block external access to port 53 unless necessary. |
| 🔄 **Update dnsmasq**     | Ensure `dnsmasq` is updated to the latest patched version. |
| 🧪 **Disable Recursion**  | If acting only as a forwarder, disable recursive DNS services for untrusted clients. |
| 🔍 **Monitor Traffic**    | Use tools like **Wireshark** or **Zeek** to log and monitor unusual DNS queries. |
| ✅ **Enable DNSSEC**      | For authoritative servers, use DNSSEC to protect against spoofing and forgery. |


