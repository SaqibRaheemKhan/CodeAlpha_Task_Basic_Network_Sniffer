#!/usr/bin/env python
"""
Beginner-Friendly Network Sniffer (Scapy with graceful fallback)
----------------------------------------------------------------

What this script does
=====================
- Captures live network packets in real-time.
- Preferred engine: **Scapy** (feature-rich, cross‑platform with Npcap on Windows).
- Graceful fallback: **raw-socket (Linux only)** if Scapy isn’t available.
- Prints a clean, readable line per packet:
  * Timestamp
  * Source address
  * Destination address
  * Protocol (TCP/UDP/ICMP/ARP/etc.)
  * Payload preview (if present)

Why you saw: `SystemExit: 1`
============================
- Earlier, the script called `sys.exit(1)` when the Scapy import failed, which
  raised `SystemExit: 1`. This version **never exits the interpreter** for that
  case. Instead, it:
  1) Tries Scapy; if unavailable, warns politely, and
  2) Automatically falls back to a simple raw-socket sniffer on **Linux**, or
  3) Exits the `main()` function cleanly with guidance on how to install Scapy.

Compatibility improvements
==========================
- Avoids `print(..., file=...)` (which breaks on certain legacy environments).
- Uses `sys.stderr.write()` for error output.
- Keeps formatting simple and portable across Python 3.x (no 3.8+ only features).

How packet sniffing works (high level)
======================================
- Your network interface (Wi‑Fi/Ethernet) sees packets as they traverse the link.
- With admin/root privileges, a sniffer can receive packets as they arrive.
- Packets are layered: Ethernet → IP/IPv6 → TCP/UDP/ICMP → Application data.
- We identify protocols either via Scapy’s layers or (in fallback) by parsing
  header bytes for EtherType, IP protocol, etc.

Legal & ethical note
====================
- Only sniff on networks you **own or have explicit permission** to test.

Self-tests (no live capture required)
=====================================
- Run `--self-test` to validate helpers. If Scapy is installed, tests include
  Scapy-built synthetic packets; otherwise, socket-parser tests run.

Usage
=====
- Linux/macOS (root required for capture):
    sudo python3 sniffer.py -i eth0 -f "tcp" -c 100
- Windows (run terminal as Administrator; install **Npcap** with WinPcap API compatible mode):
    python sniffer.py -i "Ethernet" -f "tcp"

- Engine control (optional):
    --engine auto|scapy|socket   # default: auto

- Notes:
  * `-f/--filter` uses a BPF filter **with Scapy only**. The socket fallback ignores it.
  * `-i/--iface` is honored by both engines (socket fallback binds when possible).

"""

import argparse
import datetime as dt
import os
import sys
import time
import socket
import struct

# Keep Scapy quiet before import (best-effort; scapy also respects conf.verb)
os.environ.setdefault("SCAPY_VERBOSE", "0")

SCAPY_AVAILABLE = True
try:
    from scapy.all import (
        sniff,
        Ether,
        IP,
        IPv6,
        TCP,
        UDP,
        ICMP,
        ARP,
        Raw,
        conf,
    )
except Exception:
    SCAPY_AVAILABLE = False


# -----------------
# Utility functions
# -----------------

def human_time(ts):
    """Format a UNIX timestamp as a human-friendly local time string."""
    try:
        return dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


def safe_text_preview(data, max_len=96):
    """Return a readable one-line preview of payload bytes.

    - Try to decode as UTF-8 (replacing errors).
    - Strip newlines for one-line output.
    - Truncate to `max_len` with an ellipsis if needed.
    """
    if not data:
        return ""
    if not isinstance(data, (bytes, bytearray)):
        try:
            data = bytes(data)
        except Exception:
            return ""
    text = data.decode("utf-8", errors="replace").replace("\n", " ").replace("\r", " ")
    if len(text) > max_len:
        text = text[: max_len - 1] + "…"
    return text


def print_packet_line(ts, src, dst, proto, payload_bytes, length):
    payload = safe_text_preview(payload_bytes) if payload_bytes else ""
    line = "[{ts}] {src} -> {dst} | {proto:<8} | len={length:<5}".format(
        ts=human_time(ts), src=src, dst=dst, proto=proto, length=length
    )
    if payload:
        line += " | payload: {p}".format(p=payload)
    print(line)


# ----------------------------------
# Scapy-based packet handling (preferred)
# ----------------------------------

def get_addrs(pkt):
    """Return (src, dst) addresses from IP/IPv6 if present, else Ethernet MACs."""
    if SCAPY_AVAILABLE:
        if IP in pkt:
            return pkt[IP].src, pkt[IP].dst
        if IPv6 in pkt:
            return pkt[IPv6].src, pkt[IPv6].dst
        if Ether in pkt:
            return pkt[Ether].src, pkt[Ether].dst
    return ("?", "?")


def get_protocol(pkt):
    """Return a simple protocol label from a Scapy packet."""
    if not SCAPY_AVAILABLE:
        return "Other"
    if TCP in pkt:
        return "TCP"
    if UDP in pkt:
        return "UDP"
    if ICMP in pkt:
        return "ICMP"
    if ARP in pkt:
        return "ARP"
    if IPv6 in pkt:
        return "IPv6-Other"
    if IP in pkt:
        return "IP-Other"
    if Ether in pkt:
        return "Ethernet-Other"
    return "Other"


def on_packet(pkt):
    """Scapy callback: print one tidy line for each packet."""
    ts = getattr(pkt, "time", time.time())
    src, dst = get_addrs(pkt)
    proto = get_protocol(pkt)

    payload = b""
    try:
        if SCAPY_AVAILABLE and Raw in pkt and isinstance(pkt[Raw].load, (bytes, bytearray)):
            payload = pkt[Raw].load
    except Exception:
        payload = b""

    try:
        length = len(bytes(pkt))
    except Exception:
        length = 0

    print_packet_line(ts, src, dst, proto, payload, length)


# ----------------------------------
# Linux raw-socket fallback (no Scapy)
# ----------------------------------

ETH_P_ALL = 0x0003  # all protocols (host byte order converted below)
ETH_HDR_LEN = 14


def mac_to_str(b):
    return ":".join(["%02x" % x for x in b])


def parse_ethernet(frame):
    if len(frame) < ETH_HDR_LEN:
        return None
    dst = frame[0:6]
    src = frame[6:12]
    ethertype = struct.unpack("!H", frame[12:14])[0]
    return {
        "dst_mac": mac_to_str(dst),
        "src_mac": mac_to_str(src),
        "ethertype": ethertype,
        "payload": frame[ETH_HDR_LEN:],
    }


def parse_ipv4(pkt_bytes):
    if len(pkt_bytes) < 20:
        return None
    ver_ihl = pkt_bytes[0]
    version = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4
    if version != 4 or len(pkt_bytes) < ihl:
        return None
    total_len = struct.unpack("!H", pkt_bytes[2:4])[0]
    proto = pkt_bytes[9]
    src = socket.inet_ntoa(pkt_bytes[12:16])
    dst = socket.inet_ntoa(pkt_bytes[16:20])
    payload = pkt_bytes[ihl: total_len if total_len <= len(pkt_bytes) else len(pkt_bytes)]
    return {"src": src, "dst": dst, "proto": proto, "payload": payload}


def parse_ipv6(pkt_bytes):
    if len(pkt_bytes) < 40:
        return None
    version = pkt_bytes[0] >> 4
    if version != 6:
        return None
    next_header = pkt_bytes[6]
    # hop limit = pkt_bytes[7]
    src = socket.inet_ntop(socket.AF_INET6, pkt_bytes[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, pkt_bytes[24:40])
    payload_len = struct.unpack("!H", pkt_bytes[4:6])[0]
    payload = pkt_bytes[40: 40 + payload_len if 40 + payload_len <= len(pkt_bytes) else len(pkt_bytes)]
    return {"src": src, "dst": dst, "next_header": next_header, "payload": payload}


PROTO_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


def socket_sniff(iface=None, count=0):
    if not sys.platform.startswith("linux"):
        sys.stderr.write("[!] Raw-socket fallback is only supported on Linux. Install Scapy instead.\n")
        return

    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    except PermissionError:
        sys.stderr.write("[!] Permission error: try running with sudo/root.\n")
        return
    except Exception as e:
        sys.stderr.write("[!] Could not open raw socket: {0}\n".format(e))
        return

    try:
        if iface:
            try:
                s.bind((iface, 0))
            except Exception as e:
                sys.stderr.write("[!] Could not bind to interface '{0}': {1}\n".format(iface, e))
                s.close()
                return

        seen = 0
        while True:
            if count and seen >= count:
                break
            try:
                data, addr = s.recvfrom(65535)
            except KeyboardInterrupt:
                break
            except Exception:
                continue

            ts = time.time()
            eth = parse_ethernet(data)
            if not eth:
                continue

            length = len(data)
            src = eth["src_mac"]
            dst = eth["dst_mac"]
            proto_label = "Ethernet-Other"
            payload = eth["payload"]

            if eth["ethertype"] == 0x0800:  # IPv4
                ip = parse_ipv4(payload)
                if ip:
                    src, dst = ip["src"], ip["dst"]
                    proto_label = PROTO_MAP.get(ip["proto"], "IP-Other")
                    payload = ip["payload"]
            elif eth["ethertype"] == 0x86DD:  # IPv6
                ip6 = parse_ipv6(payload)
                if ip6:
                    src, dst = ip6["src"], ip6["dst"]
                    proto_label = PROTO_MAP.get(ip6["next_header"], "IPv6-Other")
                    payload = ip6["payload"]
            elif eth["ethertype"] == 0x0806:  # ARP
                proto_label = "ARP"

            print_packet_line(ts, src, dst, proto_label, payload, length)
            seen += 1
    finally:
        try:
            s.close()
        except Exception:
            pass


# ----------------------
# Argument parsing & tests
# ----------------------

def build_arg_parser():
    p = argparse.ArgumentParser(
        description=(
            "Simple, beginner-friendly network sniffer. "
            "Default engine is 'auto' (Scapy if available, else Linux raw-socket)."
        )
    )
    p.add_argument(
        "-i",
        "--iface",
        dest="iface",
        default=None,
        help=(
            "Interface to sniff on (e.g., eth0, wlan0, en0, Ethernet). "
            "Defaults to all available if omitted."
        ),
    )
    p.add_argument(
        "-f",
        "--filter",
        dest="bpf_filter",
        default=None,
        help=(
            "BPF capture filter (Scapy engine only), e.g., 'tcp', 'udp', 'port 53'."
        ),
    )
    p.add_argument(
        "-c",
        "--count",
        dest="count",
        type=int,
        default=0,
        help=(
            "Number of packets to capture before exiting (0 = unlimited until Ctrl+C)."
        ),
    )
    p.add_argument(
        "--engine",
        choices=("auto", "scapy", "socket"),
        default="auto",
        help="Capture engine to use: auto|scapy|socket (socket = Linux only).",
    )
    p.add_argument(
        "--self-test",
        action="store_true",
        help="Run built-in tests (no live sniffing) and exit.",
    )
    return p


# ----------------------
# Built-in test routines
# ----------------------

def _assert(cond, msg):
    if not cond:
        sys.stderr.write("[TEST FAIL] {0}\n".format(msg))
        raise AssertionError(msg)


def run_self_tests():
    print("Running self-tests…")

    # Tests that do NOT require Scapy (socket-parser helpers)
    # Build a minimal Ethernet + IPv4 + TCP frame.
    dst = b"\x11\x22\x33\x44\x55\x66"
    src = b"\xaa\xbb\xcc\xdd\xee\xff"
    ethertype_ipv4 = struct.pack("!H", 0x0800)

    # IPv4 header (minimal): v4+IHL(5), TOS, total len, id, flags+frag, TTL, proto=6(TCP), csum, src, dst
    ip_ver_ihl = b"\x45"  # version 4, IHL 5 (20 bytes)
    ip_tos = b"\x00"
    payload_bytes = b"hi"  # 2 bytes
    ip_total_len = struct.pack("!H", 20 + 20 + len(payload_bytes))
    ip_id = b"\x00\x01"
    ip_flags_frag = b"\x40\x00"  # don't fragment
    ip_ttl = b"\x40"
    ip_proto_tcp = b"\x06"
    ip_checksum = b"\x00\x00"  # ignored by our parser
    ip_src = socket.inet_aton("10.0.0.1")
    ip_dst = socket.inet_aton("10.0.0.2")
    ipv4_hdr = (
        ip_ver_ihl + ip_tos + ip_total_len + ip_id + ip_flags_frag + ip_ttl + ip_proto_tcp + ip_checksum + ip_src + ip_dst
    )

    # TCP header (20 bytes minimal)
    tcp_hdr = b"\x30\x39\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x71\x10\x00\x00\x00\x00"

    ethernet_ipv4_tcp = dst + src + ethertype_ipv4 + ipv4_hdr + tcp_hdr + payload_bytes

    eth = parse_ethernet(ethernet_ipv4_tcp)
    _assert(eth is not None, "Ethernet parser should return a dict")
    _assert(eth["ethertype"] == 0x0800, "EtherType should be IPv4 (0x0800)")

    ip = parse_ipv4(eth["payload"])
    _assert(ip is not None, "IPv4 parser should return a dict")
    _assert(ip["src"] == "10.0.0.1" and ip["dst"] == "10.0.0.2", "IPv4 src/dst parsed correctly")
    _assert(ip["proto"] == 6, "IPv4 protocol should indicate TCP (6)")
    _assert(ip["payload"].endswith(payload_bytes), "Payload should be preserved")

    # Tests that REQUIRE Scapy (kept from earlier version)
    if SCAPY_AVAILABLE:
        # Test: safe_text_preview truncation and newline stripping
        long_payload = ("line1\nline2\r\n" + "A" * 200).encode("utf-8")
        preview = safe_text_preview(long_payload, max_len=20)
        _assert("\n" not in preview and "\r" not in preview, "Payload preview should be one line")
        _assert(len(preview) <= 20, "Payload preview should be truncated")

        # Construct synthetic Scapy packets
        ether = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
        ip_tcp = ether / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=80, sport=12345) / Raw(load=b"GET / HTTP/1.1\r\n\r\n")
        ip_udp = ether / IP(src="1.1.1.1", dst="8.8.8.8") / UDP(dport=53, sport=51000) / Raw(load=b"\x12\x34\x56")
        arp = ether / ARP(psrc="192.168.0.1", pdst="192.168.0.2")
        ipv6_only = ether / IPv6(src="2001:db8::1", dst="2001:db8::2")

        # Test: get_addrs
        _assert(get_addrs(ip_tcp) == ("10.0.0.1", "10.0.0.2"), "IPv4 addresses should be extracted")
        _assert(get_addrs(ip_udp) == ("1.1.1.1", "8.8.8.8"), "IPv4 addresses should be extracted (UDP)")
        _assert(get_addrs(ipv6_only) == ("2001:db8::1", "2001:db8::2"), "IPv6 addresses should be extracted")
        # Additional: ARP falls back to Ethernet MACs
        mac_src, mac_dst = ether.src, ether.dst
        _assert(get_addrs(arp) == (mac_src, mac_dst), "ARP addrs fall back to Ethernet MACs")

        # Test: get_protocol
        _assert(get_protocol(ip_tcp) == "TCP", "TCP protocol detection")
        _assert(get_protocol(ip_udp) == "UDP", "UDP protocol detection")
        _assert(get_protocol(arp) == "ARP", "ARP protocol detection")
        _assert(get_protocol(ipv6_only) in ("IPv6-Other",), "IPv6-other protocol label")

        # Test: on_packet does not crash and prints a line
        try:
            on_packet(ip_tcp)
            on_packet(ip_udp)
            on_packet(arp)
            on_packet(ipv6_only)
        except Exception as e:
            _assert(False, "on_packet should not raise: {0}".format(e))

    print("All tests passed.")


# -------------
# Main program
# -------------

def main():
    args = build_arg_parser().parse_args()

    if getattr(args, "self_test", False):
        run_self_tests()
        return

    # Minimize Scapy's chatter if present
    try:
        if SCAPY_AVAILABLE:
            conf.verb = 0
    except Exception:
        pass

    engine = args.engine
    if engine == "auto":
        engine = "scapy" if SCAPY_AVAILABLE else "socket"

    print("\n=== Beginner-Friendly Network Sniffer ===")
    print("Engine    : {0}".format(engine))
    print("Press Ctrl+C to stop. Run with permission on networks you own or are allowed to test.\n")
    if args.iface:
        print("Interface : {0}".format(args.iface))
    else:
        print("Interface : (all available)")
    if args.bpf_filter and engine == "scapy":
        print("Filter    : {0}".format(args.bpf_filter))
    elif args.bpf_filter and engine != "scapy":
        print("Filter    : (ignored by socket engine)")
    else:
        print("Filter    : (none)")
    print("Count     : {0}".format(args.count if args.count else "unlimited"))
    print("--------------------------------------------------------------")

    if engine == "scapy":
        if not SCAPY_AVAILABLE:
            sys.stderr.write("[!] Scapy is not installed. Install with: pip install scapy\n")
            if sys.platform.startswith("win"):
                sys.stderr.write("[!] Windows also requires Npcap (WinPcap API compatible mode).\n")
            return  # graceful exit
        try:
            sniff(
                iface=args.iface,
                filter=args.bpf_filter,
                prn=on_packet,
                store=False,
                count=(args.count if args.count > 0 else 0),
            )
        except KeyboardInterrupt:
            print("\n[+] Stopped by user.")
        except Exception as e:
            msg = str(e)
            if hasattr(e, "errno") and e.errno in (1, 13):  # EPERM/EACCES
                sys.stderr.write("\n[!] Permission error: try running as Administrator (Windows) or with sudo (Linux/macOS).\n")
            else:
                sys.stderr.write("\n[!] Error: {0}\n".format(msg))
        return

    # socket engine
    if engine == "socket":
        socket_sniff(iface=args.iface, count=args.count)
        return


if __name__ == "__main__":
    main()
