#!/usr/bin/env python3
"""Generate the certificates the test servers need.

Produces three application certificates:

  server_ok       2048 bit RSA, SHA-256, valid, SAN URI matches the ApplicationUri
  server_weak     1024 bit RSA, SHA-1, SAN URI does NOT match the ApplicationUri
  server_expired  2048 bit RSA, SHA-256, expired 30 days ago
  server_shared   reused by two servers, to exercise the cross-host
                  fingerprint correlation

The SHA-1 certificate is produced with the openssl CLI because current
versions of the cryptography module refuse to sign with SHA-1.
"""

import datetime
import pathlib
import subprocess
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

OUT = pathlib.Path(__file__).parent / "certs"


def make(name, bits, hash_alg, uri, days_from, days_to, common_name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OPC UA NSE Test Lab"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=days_from))
        .not_valid_after(now + datetime.timedelta(days=days_to))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=True,
                key_encipherment=True, data_encipherment=True,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(uri),
                x509.DNSName("opcua-test"),
            ]),
            critical=False,
        )
        .sign(key, hash_alg)
    )

    OUT.mkdir(exist_ok=True)
    (OUT / f"{name}_cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (OUT / f"{name}_cert.der").write_bytes(cert.public_bytes(serialization.Encoding.DER))
    (OUT / f"{name}_key.pem").write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    print(f"{name}: {bits} bit, {hash_alg.name}, "
          f"valid {days_from:+d}..{days_to:+d} days, SAN URI {uri}")


def make_sha1(name, bits, uri, days, common_name):
    """Build a SHA-1 signed certificate through the openssl CLI."""
    OUT.mkdir(exist_ok=True)
    key = OUT / f"{name}_key.pem"
    pem = OUT / f"{name}_cert.pem"
    der = OUT / f"{name}_cert.der"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", f"rsa:{bits}", "-sha1",
            "-keyout", str(key), "-out", str(pem), "-days", str(days), "-nodes",
            "-subj", f"/CN={common_name}/O=OPC UA NSE Test Lab/C=DE",
            "-addext", f"subjectAltName=URI:{uri},DNS:opcua-test",
            "-addext", "basicConstraints=critical,CA:FALSE",
        ],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["openssl", "x509", "-in", str(pem), "-outform", "DER", "-out", str(der)],
        check=True, capture_output=True,
    )
    print(f"{name}: {bits} bit, sha1, valid {days} days, SAN URI {uri}")


def main():
    # Healthy certificate: matches urn:opcua-nse:test:secure.
    make("server_ok", 2048, hashes.SHA256(),
         "urn:opcua-nse:test:secure", -1, 365, "UaServer@opcua-nse-secure")

    # Expired, and its URI does not match either.
    make("server_expired", 2048, hashes.SHA256(),
         "urn:wrong:application:uri", -800, -30, "UaServer@opcua-nse-expired")

    # Shared between two servers to trigger the fingerprint correlation.
    make("server_shared", 2048, hashes.SHA256(),
         "urn:opcua-nse:test:shared", -1, 365, "UaServer@opcua-nse-shared")

    # Weak key and weak signature; needs the openssl CLI.
    try:
        make_sha1("server_weak", 1024, "urn:wrong:application:uri", 365,
                  "UaServer@opcua-nse-legacy")
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"server_weak: skipped, openssl CLI unavailable ({exc})",
              file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
