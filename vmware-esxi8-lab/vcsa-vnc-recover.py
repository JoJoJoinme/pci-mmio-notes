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
    send_line(client, "mount -o remount,rw /")
    send_line(client, "/usr/sbin/faillock --user root --reset")
    send_line(client, "passwd", pause=4.0)
    send_line(client, password, pause=2.0)
    send_line(client, password, pause=2.0)
    send_line(
        client,
        "chage --inactive -1 --mindays 0 --maxdays 99999 --expiredate -1 root",
    )
    send_line(client, "sync")
    if args.capture:
        client.captureScreen(args.capture)

    # ThreadedVNCClientProxy.disconnect can hang against Workstation's VNC
    # server after a capture. This is a one-shot helper, so process exit is the
    # reliable connection teardown.
    os._exit(0)


if __name__ == "__main__":
    main()
