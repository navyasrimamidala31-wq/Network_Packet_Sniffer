#!/usr/bin/env python3
"""
Network Packet Sniffer
Educational/authorized-use example.

Captures IPv4 packets using a raw socket, parses IP/TCP/UDP headers,
and records packet summary statistics in a log file.
"""

import argparse
import socket
import struct
from collections import Counter
from datetime import datetime


PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


def parse_ipv4_packet(packet):
    """Parse an IPv4 packet and return useful header information."""
    if len(packet) < 20:
        return None

    version_ihl = packet[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4

    if version != 4 or len(packet) < ihl:
        return None

    protocol_number = packet[9]
    source_ip = socket.inet_ntoa(packet[12:16])
    destination_ip = socket.inet_ntoa(packet[16:20])
    ttl = packet[8]

    protocol = PROTOCOLS.get(protocol_number, f"OTHER({protocol_number})")

    source_port = "-"
    destination_port = "-"

    transport = packet[ihl:]

    if protocol_number in (6, 17) and len(transport) >= 4:
        source_port, destination_port = struct.unpack("!HH", transport[:4])

    if protocol_number == 6 and len(transport) >= 20:
        tcp_header_length = (transport[12] >> 4) * 4
        payload = transport[tcp_header_length:]
    elif protocol_number == 17 and len(transport) >= 8:
        payload = transport[8:]
    else:
        payload = transport

    return {
        "source": source_ip,
        "destination": destination_ip,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "ttl": ttl,
        "payload": payload[:16].hex(" "),
        "length": len(packet),
    }


def create_raw_socket():
    """Create an IPv4 raw socket."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return sock


def main():
    parser = argparse.ArgumentParser(
        description="Educational IPv4 TCP/UDP packet sniffer"
    )
    parser.add_argument(
        "-n", "--count", type=int, default=10,
        help="number of packets to capture (default: 10)"
    )
    parser.add_argument(
        "-l", "--log", default="network_log.txt",
        help="output log file"
    )
    args = parser.parse_args()

    if args.count <= 0:
        parser.error("--count must be greater than zero")

    try:
        sock = create_raw_socket()
    except PermissionError:
        print("Permission denied. Run as administrator/root.")
        return 1
    except OSError as error:
        print(f"Unable to create raw socket: {error}")
        return 1

    counts = Counter()
    total_bytes = 0
    captured = 0

    print(f"Capturing {args.count} IPv4 packets...")
    print(f"Log file: {args.log}")

    with sock, open(args.log, "w", encoding="utf-8") as log:
        log.write("NETWORK PACKET SNIFFER LOG\n")
        log.write("=" * 70 + "\n")
        log.write(
            f"Started: {datetime.now().isoformat(timespec='seconds')}\n\n"
        )

        while captured < args.count:
            packet, _ = sock.recvfrom(65535)

            parsed = parse_ipv4_packet(packet)
            if parsed is None:
                continue

            captured += 1
            total_bytes += parsed["length"]
            counts[parsed["protocol"]] += 1

            line = (
                f"{captured:03d} | "
                f"{parsed['source']}:{parsed['source_port']} -> "
                f"{parsed['destination']}:{parsed['destination_port']} | "
                f"{parsed['protocol']} | "
                f"TTL={parsed['ttl']} | "
                f"BYTES={parsed['length']} | "
                f"PAYLOAD={parsed['payload']}\n"
            )

            print(line, end="")
            log.write(line)

        log.write("\nSUMMARY\n")
        log.write("-" * 70 + "\n")
        log.write(f"Packets captured: {captured}\n")
        log.write(f"Total bytes: {total_bytes}\n")

        for protocol, count in sorted(counts.items()):
            log.write(f"{protocol}: {count}\n")

    print("\nCapture complete.")
    print(f"Packets captured: {captured}")
    print(f"Total bytes: {total_bytes}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
