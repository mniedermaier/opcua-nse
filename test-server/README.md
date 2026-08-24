# OPC UA test matrix

Nine OPC UA servers covering three independent implementations - asyncua
(Python), open62541 (C) and node-opcua (JavaScript). Six of them reproduce one
configuration each of the NSE scripts' checks and are built from one image and
one script (`servers.py`), selected by `--mode`; the other three are separate
images under `stacks/`.

Running more than one implementation is the point: they disagree on encoding
details, and those disagreements are where a decoder bug hides. Both bugs found
so far - GUID NodeIds written back as null, and a wrong StatusCode table - only
became visible once open62541 joined the matrix.

| Port | Mode | Certificate | Policies | What it exercises |
| --- | --- | --- | --- | --- |
| 4840 | `insecure` | none | None | The common misconfiguration: no security, anonymous full access, writable process variables, valid credentials for the brute script |
| 4855 | `secure` | 2048 bit, SHA-256, matching URI | None, Basic256Sha256, Aes128Sha256RsaOaep, Aes256Sha256RsaPss (Sign and SignAndEncrypt) | Seven endpoints - large enough that the reply is chunked when the client advertises a small buffer |
| 4885 | `legacy` | 1024 bit, SHA-1, wrong URI | None, Basic128Rsa15, Basic256 | Deprecated policies, weak key, weak hash, ApplicationUri mismatch |
| 4897 | `expired` | 2048 bit, expired 30 days ago | None, Basic256Sha256 | Expired certificate, plus anonymous sessions denied read access so the scripts have to report enforced access control |
| 4845 | `fault` | none | none | Replies to every handshake with `ERRF` and `Bad_TcpEndpointUrlInvalid`, so the scripts' error path is covered - a rejection still identifies the protocol |
| 4843 | `lds` | built in | None | An open62541 Local Discovery Server with the multicast extension. The only server here that answers `FindServersOnNetwork`, which it does from its own registration cache |
| 48020 | `open62541` | built in | None | A second implementation, in C. Uses string NodeIds and hands out GUID authentication tokens, which is where the NSE client's NodeId handling gets exercised |
| 48030 | `node-opcua` | generated at startup | None, Basic256Sha256 | A third implementation, in JavaScript, with its own encoding choices and its own idea of what an empty RoleSet looks like |
| 48010 | `shared-a` | shared certificate | None, Basic256Sha256 | Certificate fingerprint correlation across hosts |
| 62541 | `shared-b` | the same shared certificate | None, Basic256Sha256 | The other half of the correlation |

The ports are real OPC UA vendor ports (4855, 4885 and 4897 are registered OPC
UA ports; 48010 is used by Unified Automation's UaGateway, 62541 by the OPC
Foundation reference stack), so the scripts' port rule matches without special
casing.

## Starting the matrix

```bash
pip install cryptography          # only needed for certificate generation
python3 gen_certs.py              # writes certs/, including broken certificates
docker compose up -d --build
docker compose ps
```

`servers.py` and `certs/` are mounted into the containers, so editing the server
needs only `docker compose restart`, not a rebuild.

## The hostile server

`hostile_server.py` is a separate process serving seven ports, each with one
attack. It completes HEL/ACK and OpenSecureChannel correctly — the attacks only
start once the client asks a service request, which is where a real hostile peer
would strike too.

| Port | Attack |
| --- | --- |
| 26543 | an endpoints array claiming 4 294 967 290 entries |
| 48040 | an unbounded stream of intermediate chunks, never a final one |
| 48050 | a header promising 100 kB more than follows |
| 49320 | a string with length -2, which is not the null marker |
| 49380 | a chunk type the specification does not define |
| 51210 | a string claiming to be 2 GB long |
| 53530 | one byte every two seconds, forever |

The suite asserts that each is refused inside a time budget, with a message
naming the problem, and without the script erroring out.

## Certificates

`gen_certs.py` produces four certificates:

| Name | Key | Signature | Validity | subjectAltName URI |
| --- | --- | --- | --- | --- |
| `server_ok` | RSA 2048 | SHA-256 | one year | matches the ApplicationUri |
| `server_weak` | RSA 1024 | SHA-1 | one year | deliberately wrong |
| `server_expired` | RSA 2048 | SHA-256 | expired 30 days ago | deliberately wrong |
| `server_shared` | RSA 2048 | SHA-256 | one year | matches, and is reused by two servers |

The SHA-1 certificate is created through the `openssl` CLI, because current
versions of the Python `cryptography` module refuse to sign with SHA-1. If
`openssl` is missing, that one certificate is skipped and the `legacy` server
falls back to the remaining checks.

## Credentials

The `insecure`, `secure` and `legacy` servers accept two accounts, which is what
`opcua-brute` is expected to find:

```
operator / operator
engineer / Password1
```

Everything else is rejected with `Bad_SecurityChecksFailed`.

## Address space

Every server exposes a small plant model under `Objects/Plant`:

| Node | Access |
| --- | --- |
| `Temperature` | read + write |
| `Pressure` | read + write |
| `Setpoint` | read + write |
| `SerialNumber` | read only |
| `Multiply` | callable method |

`opcua-browse` is expected to list exactly the three writable variables and to
leave `SerialNumber` out of that list.

## Running a single server without docker

```bash
pip install -r requirements.txt
python3 servers.py --mode secure --port 4855
```

The other two stacks live in `stacks/open62541` and `stacks/node-opcua` and are
built by docker compose; open62541 is compiled from a pinned release, which is
the slowest part of a cold build.

## Scanning it

```bash
cd ..
nmap -p 4840,4855,4885,4897,48010,62541 --script ./opcua-discover.nse localhost
./test/run-tests.sh
```
