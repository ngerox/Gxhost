#!/usr/bin/env python3
"""Simple network connectivity check."""
import socket
import sys

def check_network():
    try:
        # Try to connect to Google's DNS
        socket.create_connection(("8.8.8.8", 53), timeout=5)
        sys.exit(0)
    except OSError:
        sys.exit(1)

if __name__ == "__main__":
    check_network()
