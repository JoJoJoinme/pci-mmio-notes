#!/usr/bin/env python3
import argparse
import os
import time

from vncdotool import api


def send_line(client, line, pause=1.0):
    for character in line:
        client.keyPress(character)
    client.keyPress("enter")
    time.sleep(pause)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default="127.0.0.1::5907")
    parser.add_argument("--capture")
    args = parser.parse_args()

    password = os.environ.get("VCSA_ROOT_PASSWORD")
    if not password:
        raise SystemExit("VCSA_ROOT_PASSWORD is required")

    client = api.connect(args.server)
    send_line(client, "root")
    send_line(client, password, pause=4.0)
    send_line(client, "shell.set --enabled true")
    send_line(client, "shell", pause=2.0)
    send_line(client, "systemctl enable --now sshd", pause=3.0)
    send_line(
        client,
        "ip route replace 172.31.91.0/24 via 192.168.91.1",
        pause=2.0,
    )
    if args.capture:
        client.captureScreen(args.capture)
    os._exit(0)


if __name__ == "__main__":
    main()
