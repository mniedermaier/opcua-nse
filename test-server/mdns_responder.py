#!/usr/bin/env python3
"""Announces an OPC UA server over multicast DNS.

OPC 10000-12 has a Local Discovery Server with the multicast extension announce
its servers as _opcua-tcp._tcp.local, which is what
broadcast-opcua-discover.nse looks for. No stack in the test matrix does this,
so this responder stands in for one.

Needs the host network to receive multicast, which is why the compose service
runs with network_mode: host.

  python3 mdns_responder.py --port 4840 --name "OPC UA Test Server"
"""

import argparse
import logging
import socket
import time

from zeroconf import ServiceInfo, Zeroconf

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("opcua-mdns")


def local_address():
    """Best guess at the address other hosts would reach us on."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 9))       # never sends anything
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=4840)
    parser.add_argument("--name", default="OPC UA Test Server")
    parser.add_argument("--path", default="/nse/")
    parser.add_argument("--address", default=None)
    args = parser.parse_args()

    address = args.address or local_address()
    hostname = socket.gethostname()

    info = ServiceInfo(
        "_opcua-tcp._tcp.local.",
        f"{args.name}._opcua-tcp._tcp.local.",
        addresses=[socket.inet_aton(address)],
        port=args.port,
        # The properties an LDS-ME announces alongside the service.
        properties={
            "path": args.path,
            "caps": "LDS,DA",
        },
        server=f"{hostname}.local.",
    )

    zeroconf = Zeroconf()
    zeroconf.register_service(info)
    logger.info("announcing %s on %s:%d as _opcua-tcp._tcp.local",
                args.name, address, args.port)

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        zeroconf.unregister_service(info)
        zeroconf.close()


if __name__ == "__main__":
    main()
