#!/usr/bin/env python3
"""A deliberately hostile OPC UA endpoint.

The scripts get pointed at unknown ports, so a peer may answer whatever it
likes. This server speaks the handshake correctly - HEL/ACK and
OpenSecureChannel - and only then starts lying, one attack per port:

  26543  huge-array       an endpoints array claiming four billion entries
  48040  endless-chunks   an unbounded stream of intermediate chunks
  48050  truncated        a header promising far more bytes than follow
  49320  negative-length  a string with length -2, which is not the null marker
  49380  bad-chunk-type   a chunk type the specification does not define
  51210  giant-string     a string claiming to be 2 GB long
  53530  slow-drip        one byte every two seconds, forever

A client that handles these correctly gives up quickly, says why, and never
allocates what the peer asks it to.

  python3 hostile_server.py
"""

import argparse
import logging
import socket
import socketserver
import struct
import threading
import time

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("opcua-hostile")

ATTACKS = {
    26543: "huge-array",
    48040: "endless-chunks",
    48050: "truncated",
    49320: "negative-length",
    49380: "bad-chunk-type",
    51210: "giant-string",
    53530: "slow-drip",
}


def u32(value):
    return struct.pack("<I", value)


def i32(value):
    return struct.pack("<i", value)


def ua_string(text):
    if text is None:
        return i32(-1)
    raw = text.encode("utf-8")
    return i32(len(raw)) + raw


def message(kind, chunk, body):
    """Wraps a body in a UACP message header."""
    return kind.encode("ascii") + chunk.encode("ascii") + u32(8 + len(body)) + body


def ack():
    body = u32(0) + u32(65535) + u32(65535) + u32(0) + u32(0)
    return message("ACK", "F", body)


def response_header(status=0):
    """A ResponseHeader with no diagnostics and no additional header."""
    return (
        struct.pack("<Q", 0)     # Timestamp
        + u32(1)                 # RequestHandle
        + u32(status)            # ServiceResult
        + b"\x00"                # ServiceDiagnostics
        + i32(-1)                # StringTable
        + b"\x00\x00\x00"        # AdditionalHeader
    )


def open_secure_channel_response(request_id):
    """A valid OpenSecureChannelResponse, so the client proceeds to a request."""
    body = (
        b"\x01\x00" + struct.pack("<H", 449)   # TypeId, four byte NodeId
        + response_header()
        + u32(0)                               # ServerProtocolVersion
        + u32(1)                               # SecurityToken.ChannelId
        + u32(1)                               # SecurityToken.TokenId
        + struct.pack("<Q", 0)                 # CreatedAt
        + u32(600000)                          # RevisedLifetime
        + i32(-1)                              # ServerNonce
    )
    header = (
        u32(1)                                 # SecureChannelId
        + ua_string("http://opcfoundation.org/UA/SecurityPolicy#None")
        + i32(-1)                              # SenderCertificate
        + i32(-1)                              # ReceiverCertificateThumbprint
        + u32(1)                               # SequenceNumber
        + u32(request_id)                      # RequestId
    )
    return message("OPN", "F", header + body)


def msg_chunk(payload, chunk="F", channel=1, token=1, sequence=2, request=2):
    header = u32(channel) + u32(token) + u32(sequence) + u32(request)
    return message("MSG", chunk, header + payload)


def get_endpoints_prefix():
    """TypeId of a GetEndpointsResponse plus a good ResponseHeader."""
    return b"\x01\x00" + struct.pack("<H", 431) + response_header()


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        attack = self.server.attack
        sock = self.request
        sock.settimeout(30)
        peer = self.client_address[0]

        try:
            data = sock.recv(8192)
            if not data[:3] == b"HEL":
                return
            sock.sendall(ack())

            data = sock.recv(8192)
            if not data[:3] == b"OPN":
                return
            sock.sendall(open_secure_channel_response(1))

            data = sock.recv(8192)
            if not data[:3] == b"MSG":
                return
            logger.info("%s asked a service request, answering with %s",
                        peer, attack)
            getattr(self, f"attack_{attack.replace('-', '_')}")(sock)
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            logger.info("%s went away", peer)
        except Exception as exc:  # noqa: BLE001 - a test server may fail loudly
            logger.warning("%s handler error: %s", peer, exc)

    # One attack per method ------------------------------------------------

    def attack_huge_array(self, sock):
        """Claims 4 294 967 290 endpoints and sends none of them."""
        payload = get_endpoints_prefix() + u32(0xFFFFFFFA)
        sock.sendall(msg_chunk(payload))

    def attack_giant_string(self, sock):
        """First endpoint's URL claims to be 2 GB long."""
        payload = get_endpoints_prefix() + u32(1) + i32(0x7FFFFFFF)
        sock.sendall(msg_chunk(payload))

    def attack_negative_length(self, sock):
        """A string length of -2, which is neither valid nor the null marker."""
        payload = get_endpoints_prefix() + u32(1) + i32(-2)
        sock.sendall(msg_chunk(payload))

    def attack_truncated(self, sock):
        """Announces a large message and then stops sending."""
        header = u32(1) + u32(1) + u32(2) + u32(2)
        body = header + get_endpoints_prefix()
        sock.sendall(b"MSGF" + u32(8 + len(body) + 100000) + body)

    def attack_bad_chunk_type(self, sock):
        """Uses a chunk type the specification does not define."""
        sock.sendall(msg_chunk(get_endpoints_prefix(), chunk="X"))

    def attack_endless_chunks(self, sock):
        """Sends intermediate chunks forever, never a final one."""
        filler = b"\x00" * 4096
        sequence = 2
        while True:
            sock.sendall(msg_chunk(filler, chunk="C", sequence=sequence))
            sequence += 1
            time.sleep(0.01)

    def attack_slow_drip(self, sock):
        """Sends one byte of a message header every two seconds."""
        for byte in b"MSGF" + u32(100000):
            sock.sendall(bytes([byte]))
            time.sleep(2)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    address_family = socket.AF_INET

    def __init__(self, address, handler, attack):
        self.attack = attack
        super().__init__(address, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", type=int, default=None,
                        help="serve a single port instead of all of them")
    args = parser.parse_args()

    ports = {args.only: ATTACKS[args.only]} if args.only else ATTACKS

    for port, attack in sorted(ports.items()):
        server = Server(("0.0.0.0", port), Handler, attack)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        logger.info("port %d serves the %s attack", port, attack)

    logger.info("hostile server ready on %d ports", len(ports))
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
