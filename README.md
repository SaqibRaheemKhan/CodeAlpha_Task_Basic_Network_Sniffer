# CodeAlpha_Task_Basic_Network_Sniffer
## 📄 README.md

````markdown
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
````

---

## ⚙️ Usage

Run with root/administrator privileges (required for sniffing):

```bash
sudo python sniffer.py [OPTIONS]
```

Examples:

```bash
# Capture 10 packets
sudo python sniffer.py -c 10

# Capture only TCP packets on eth0
sudo python sniffer.py -i eth0 -f "tcp"

# Run self-tests
python sniffer.py --self-test
```

👉 For full command-line options and troubleshooting, see [USAGE.md](USAGE.md).

---

## ⚠️ Disclaimer

This tool is for **educational purposes only**.
Use it responsibly on networks you own or have explicit permission to analyze. Unauthorized sniffing may be illegal.

````

---

## 📄 USAGE.md  

```markdown
# 📖 Usage Guide – Simple Python Network Sniffer

This document provides detailed instructions on using the sniffer.

---

## 🛠️ Command-Line Options

| Flag | Description |
|------|-------------|
| `-i`, `--iface` | Network interface to sniff on (default: system default) |
| `-c`, `--count` | Number of packets to capture (default: unlimited) |
| `-f`, `--filter` | BPF filter (e.g., `"tcp"`, `"udp"`, `"icmp"`) – Scapy only |
| `--engine {auto,scapy,socket}` | Select capture engine (default: auto) |
| `--self-test` | Run built-in tests without capturing live packets |

---

## 🔍 Examples

Capture **10 packets** on default interface:
```bash
sudo python sniffer.py -c 10
````

Capture only **TCP packets** on `eth0`:

```bash
sudo python sniffer.py -i eth0 -f "tcp"
```

Force **raw-socket engine** (Linux only):

```bash
sudo python sniffer.py --engine socket
```

Run **self-tests**:

```bash
python sniffer.py --self-test
```

---

## 🧰 Troubleshooting

### 1. Permission Errors

* On Linux/macOS: run with `sudo`
* On Windows: run in Administrator Command Prompt or PowerShell

### 2. Scapy Not Installed

* Install it with:

  ```bash
  pip install scapy
  ```
* Or use `--engine socket` (Linux only)

### 3. No Packets Captured

* Ensure you selected the correct network interface with `-i`
* Try running `ifconfig` (Linux/macOS) or `ipconfig` (Windows) to list interfaces

---

## 📘 Learning Notes

* **IP headers** contain source/destination addresses
* **Transport headers** (TCP/UDP) define communication type
* **Payloads** hold application data (may be empty or encrypted)

---

## ⚠️ Disclaimer

This project is strictly for **learning purposes**.
Do not use on networks you don’t own or without explicit permission.

```

---

Would you like me to also create a **`CONTRIBUTING.md`** (for future collaborators) and a **`LICENSE`** file (MIT or GPL) to make your repo fully professional?
```
