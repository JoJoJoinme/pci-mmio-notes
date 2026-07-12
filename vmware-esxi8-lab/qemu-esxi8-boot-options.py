#!/usr/bin/env python3
import argparse
import socket
import time
from pathlib import Path


BOOT_MARKER = 'BdsDxe: starting Boot0001'
KEY_NAMES = {
    ' ': 'spc',
    '=': 'equal',
    '-': 'minus',
    '.': 'dot',
    '/': 'slash',
    ',': 'comma',
}


def marker_count(path: Path) -> int:
    try:
        return path.read_text(encoding='utf-8', errors='ignore').count(BOOT_MARKER)
    except FileNotFoundError:
        return 0


def send_monitor(sock: socket.socket, command: str, delay: float = 0.03) -> None:
    sock.sendall(command.encode('ascii') + b'\n')
    time.sleep(delay)
    try:
        sock.recv(65536)
    except TimeoutError:
        pass


def key_name(char: str) -> str:
    if char in KEY_NAMES:
        return KEY_NAMES[char]
    if char.isalpha():
        return f'shift-{char.lower()}' if char.isupper() else char
    if char.isdigit():
        return char
    raise ValueError(f'No QEMU sendkey mapping for {char!r}')


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--options',
        default=' enablePCIErrors=TRUE pcipDisablePciErrReporting=FALSE',
    )
    parser.add_argument('--serial', default='/root/vm/esxi8-mf/serial.log')
    parser.add_argument('--monitor', default='/root/vm/esxi8-mf/monitor.sock')
    parser.add_argument('--timeout', type=float, default=180)
    parser.add_argument('--post-marker-delay', type=float, default=0.3)
    args = parser.parse_args()

    serial_path = Path(args.serial)
    initial_count = marker_count(serial_path)
    deadline = time.monotonic() + args.timeout
    while marker_count(serial_path) <= initial_count:
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f'No new {BOOT_MARKER!r} marker after {args.timeout} seconds'
            )
        time.sleep(0.1)

    time.sleep(args.post_marker_delay)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        sock.connect(args.monitor)
        time.sleep(0.1)
        try:
            sock.recv(65536)
        except TimeoutError:
            pass
        send_monitor(sock, 'sendkey shift-o', delay=1.0)
        for char in args.options:
            send_monitor(sock, f'sendkey {key_name(char)}')
        send_monitor(sock, 'sendkey ret', delay=0.1)

    print(
        f'Injected {args.options!r} after boot marker '
        f'{initial_count} -> {marker_count(serial_path)}'
    )


if __name__ == '__main__':
    main()
