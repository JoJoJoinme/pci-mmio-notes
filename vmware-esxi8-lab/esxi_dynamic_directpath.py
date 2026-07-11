#!/usr/bin/env python3
import argparse
import atexit
import json
import os
import re
import ssl
import subprocess

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim


def caveat_password(caveat_id: str) -> str:
    entry = subprocess.run(
        ["caveat", "show", caveat_id],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    match = re.search(r"Password:\s*(\S+)", entry)
    if not match:
        raise RuntimeError(f"Caveat {caveat_id!r} does not contain a Password field")
    return match.group(1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="169.254.239.77")
    parser.add_argument("--user", default="root")
    parser.add_argument("--caveat", default="esxi8-auto-codex-credentials")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        os.environ.pop(name, None)
    os.environ["NO_PROXY"] = args.host

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    service_instance = SmartConnect(
        host=args.host,
        user=args.user,
        pwd=caveat_password(args.caveat),
        sslContext=context,
    )
    atexit.register(Disconnect, service_instance)

    content = service_instance.RetrieveContent()
    view = content.viewManager.CreateContainerView(content.rootFolder, [vim.HostSystem], True)
    try:
        hosts = list(view.view)
    finally:
        view.Destroy()
    if len(hosts) != 1:
        raise RuntimeError(f"Expected one ESXi host, found {len(hosts)}")

    host = hosts[0]
    manager = host.configManager.assignableHardwareManager
    candidates = manager.RetrieveDynamicPassthroughInfo()
    result = {
        "esxi": host.config.product.fullName,
        "manager": str(manager),
        "candidateCount": len(candidates),
        "candidates": [
            {
                "name": candidate.name,
                "vendorName": candidate.vendorName,
                "deviceName": candidate.deviceName,
                "vendorId": candidate.vendorId,
                "deviceId": candidate.deviceId,
                "customLabel": candidate.customLabel,
            }
            for candidate in candidates
        ],
    }
    with open(args.output, "w", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
