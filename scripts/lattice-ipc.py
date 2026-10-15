#!/usr/bin/env python3
"""Minimal lattice-node IPC client for automation.

Sends one JSON-line request to the node IPC socket and prints the response.
Secrets pass via arguments or environment, never stored.
"""
import argparse
import json
import os
import socket
import sys

DEFAULT_SOCKET = "/tmp/lattice-node.sock"


def send(socket_path, request):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(60)
    client.connect(socket_path)
    with client:
        client.sendall((json.dumps(request) + "\n").encode())
        chunks = []
        while True:
            data = client.recv(65536)
            if not data:
                break
            chunks.append(data)
            if b"\n" in data:
                break
        return b"".join(chunks).decode()


def main():
    parser = argparse.ArgumentParser(description="lattice-node IPC client")
    parser.add_argument("--socket", default=os.environ.get("LATTICE_SOCKET", DEFAULT_SOCKET))
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("ping")
    sub.add_parser("status")
    sub.add_parser("config")
    sub.add_parser("enrollment-status")
    sub.add_parser("network-status")
    sub.add_parser("reset-enrollment")
    sub.add_parser("reset-bootstrap")

    enroll = sub.add_parser("enroll")
    enroll.add_argument("--url", required=True)
    enroll.add_argument("--token", default=os.environ.get("LATTICE_ENROLLMENT_TOKEN", ""))

    enroll_boot = sub.add_parser("enroll-bootstrap")
    enroll_boot.add_argument("--url", required=True)
    enroll_boot.add_argument("--token", default=os.environ.get("LATTICE_ENROLLMENT_TOKEN", ""))

    net = sub.add_parser("set-network-enabled")
    net.add_argument("--enabled", required=True, choices=["true", "false"])

    args = parser.parse_args()

    if args.command == "ping":
        request = {"method": "ping"}
    elif args.command == "status":
        request = {"method": "get_status"}
    elif args.command == "config":
        request = {"method": "get_config"}
    elif args.command == "enrollment-status":
        request = {"method": "get_enrollment_status"}
    elif args.command == "network-status":
        request = {"method": "get_network_status"}
    elif args.command == "reset-enrollment":
        request = {"method": "reset_enrollment"}
    elif args.command == "reset-bootstrap":
        request = {"method": "reset_bootstrap"}
    elif args.command == "enroll":
        request = {"method": "enroll", "params": {"control_url": args.url, "enrollment_token": args.token}}
    elif args.command == "enroll-bootstrap":
        request = {
            "method": "enroll_bootstrap",
            "params": {"bootstrap_url": args.url, "enrollment_token": args.token},
        }
    elif args.command == "set-network-enabled":
        request = {"method": "set_network_enabled", "params": {"enabled": args.enabled == "true"}}

    try:
        print(send(args.socket, request))
    except Exception as error:
        print(f"IPC request failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
