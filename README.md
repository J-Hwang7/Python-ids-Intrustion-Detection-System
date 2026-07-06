# Python-Intrusion-Detection-System
Similar to a guard dog or a security booth, an **Intrusion Detection System (IDS)** looks for potential signs of intruders. By utilizing **Scapy**, a Python library, one can develop an IDS tool that sniffs live network traffic and flags SYN port scans to help prevent potential SYN flood attacks from occurring. It is crucial to prevent SYN flood attacks because of their ability to prevent new client-server connections, cause server crashes, and slow network functionality.

**Author:** @J-Hwang7 **Date** July 2026

# How it works
By utilizing **scan_tracker**, the IDS maps each source IP to the port and timestamp at which it recently sent a SYN request. Afterwards, **is_syn_scan_packet** and **detect_port_scan(src_ip, dst_port)** are used to verify if the connection has an **ACK** flag and count the distinct ports that an IP address has SYN requests, within the last few seconds, to determine if a SYN port scan occurs. 

# Python IDS Procedures
**Prerequisite Installation**
- Npcap 1.88 for Windows

**Creating IDS**

In a Linux terminal, create a new directory to house this project.

Afterwards, run these commands in the directory to install **Scapy** onto your machine.
```
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install scapy
```
