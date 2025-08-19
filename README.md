# CodeAlpha_Task_Basic_Network_Sniffer
# 🕵️ Simple Python Network Sniffer

A beginner-friendly Python program that captures and analyzes live network traffic in real-time.  
This tool is designed to help learners understand how packets flow across a network and how to parse them using Python.  

It supports:
- **Scapy engine** (preferred, if installed)
- **Raw socket fallback** (Linux only, when Scapy isn’t available)

---

## ✨ Features
- Captures packets in real-time  
- Extracts and displays:
  - Source IP
  - Destination IP
  - Protocol type (TCP, UDP, ICMP, etc.)
  - Payload (if available)  
- Self-test mode (`--self-test`) to verify functionality  
- Modular design: choose between **Scapy** and **socket** engines  

---

## 📦 Requirements
- **Python 3.6+**  
- Recommended: [Scapy](https://scapy.net/)  

Install Scapy:
```bash
pip install scapy
