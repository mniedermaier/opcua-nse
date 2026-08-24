#!/usr/bin/env python3
"""A minimal OPC UA endpoint that only ever answers with ERR.

Real servers reject a handshake when the endpoint URL does not match their
configuration, and that rejection is itself proof that the peer speaks OPC UA.
No full stack reproduces that on demand, so this server does: it reads a HEL
message and replies with ERRF carrying Bad_TcpEndpointUrlInvalid (0x80830000).

  python3 fault_server.py --port 4845 [--status 0x80830000]
"""

import argparse
import socket
import socketserver
import struct
import logging

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("opcua-fault")

STATUS = 0x80830000
REASON = "The endpoint URL is not supported by this server."


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(8192)
        if not data:
            return
        logger.info("%s sent %d bytes: %s", self.client_address[0], len(data),
                    data[:4].decode("ascii", "replace"))

        reason = REASON.encode("utf-8")
        body = struct.pack("<I", self.server.status_code)
        body += struct.pack("<i", len(reason)) + reason
        message = b"ERRF" + struct.pack("<I", 8 + len(body)) + body
        self.request.sendall(message)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    address_family = socket.AF_INET

    def __init__(self, address, handler, status_code):
        self.status_code = status_code
        super().__init__(address, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=4845)
    parser.add_argument("--status", default=hex(STATUS),
                        help="StatusCode to return, e.g. 0x80830000")
    args = parser.parse_args()

    status_code = int(args.status, 0)
    logger.info("answering every handshake on port %d with ERR 0x%08X",
                args.port, status_code)
    Server(("0.0.0.0", args.port), Handler, status_code).serve_forever()


if __name__ == "__main__":
    main()
