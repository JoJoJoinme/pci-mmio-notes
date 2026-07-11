#!/usr/bin/env python3
import socket
import sys
import time

sock_path = "/root/vm/esxi8-mf/monitor.sock"
commands = sys.argv[1:]
if not commands:
    raise SystemExit("usage: qemu-esxi8-monitor-command.py COMMAND [COMMAND ...]")

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
    sock.settimeout(2)
    sock.connect(sock_path)
    time.sleep(0.1)
    try:
        sys.stdout.buffer.write(sock.recv(65536))
    except TimeoutError:
        pass
    for command in commands:
        sock.sendall(command.encode("ascii") + b"\n")
        time.sleep(0.2)
        try:
            sys.stdout.buffer.write(sock.recv(65536))
        except TimeoutError:
            pass
