# OPC UA NSE Scripts

[![tests](https://github.com/mniedermaier/opcua-nse/actions/workflows/ci.yml/badge.svg)](https://github.com/mniedermaier/opcua-nse/actions/workflows/ci.yml)
[![nmap](https://img.shields.io/badge/nmap-7.94%2B-1B5E8C)](https://nmap.org/)
[![lua](https://img.shields.io/badge/lua-5.4-1B5E8C)](https://www.lua.org/)
[![license](https://img.shields.io/badge/license-Nmap-brightgreen)](https://nmap.org/book/man-legal.html)

Discover and audit OPC UA (IEC 62541) servers with Nmap — endpoints, security
policies, application certificates and access levels, in one scan.

Nmap ships no OPC UA script and no OPC UA service probe. The two third party
scripts that exist stop right after the HEL/ACK handshake. These scripts go the
whole way: secure channel, chunked message assembly, endpoint enumeration,
certificate analysis, sessions, address space browsing and credential guessing —
in plain Lua, with no Python runtime, in a single `nmap` invocation.

```console
$ nmap -p 4885 --script opcua-discover 192.0.2.10

PORT     STATE SERVICE
4885/tcp open  opcua-tcp
| opcua-discover:
|   Protocol: OPC UA Binary (opc.tcp)
|   Transport: protocol version 0, receive buffer 65535, send buffer 65535, max message 104857600, max chunks 1601
|   Server:
|     Application Name: OPC UA Test Server (legacy crypto)
|     Application URI: urn:opcua-nse:test:legacy
|     Application Type: ClientAndServer
|   Endpoints (5):
|     1:
|       URL: opc.tcp://192.0.2.10:4885/nse/
|       Security: None / None (level 0)
|       User tokens: Anonymous [None], UserName [Basic128Rsa15]
|     2:
|       URL: opc.tcp://192.0.2.10:4885/nse/
|       Security: Sign / Basic128Rsa15 (level 1)
|       User tokens: Anonymous [None], UserName [Basic128Rsa15]
|   Server Certificate:
|     Subject: UaServer@opcua-nse-legacy, OPC UA NSE Test Lab, DE
|     Issuer: UaServer@opcua-nse-legacy, OPC UA NSE Test Lab, DE (self-signed)
|     Valid: 2026-08-24 13:11:38 UTC - 2027-08-24 13:11:38 UTC
|     Key: rsa 1024 bits, sha1WithRSAEncryption
|     ApplicationUri (SAN): urn:wrong:application:uri
|     SHA-256: E07B682FDF076A2BCBF139163E1F399EBB4F7211ED39446DF378E65230237A0D
|     Issues:
|       HIGH: weak 1024 bit RSA key
|       HIGH: weak certificate signature algorithm: sha1WithRSAEncryption
|       MEDIUM: certificate URI does not match ApplicationUri (urn:wrong:application:uri vs urn:opcua-nse:test:legacy)
|       LOW: certificate is self-signed
|   Security Findings:
|     HIGH: Anonymous access allowed (endpoints 1, 2, 3, 4, 5)
|     HIGH: No securely configured endpoint
|     HIGH: SecurityMode None (endpoint 1)
|     MEDIUM: Deprecated SecurityPolicy Basic128Rsa15 (endpoints 2, 3)
|_    MEDIUM: Deprecated SecurityPolicy Basic256 (endpoints 4, 5)
```

## Contents

- [The scripts](#the-scripts)
- [Installation](#installation)
- [opcua-discover](#opcua-discover)
- [opcua-info](#opcua-info)
- [opcua-browse](#opcua-browse)
- [opcua-brute](#opcua-brute)
- [Service probe for -sV](#service-probe-for--sv)
- [Ports](#ports)
- [Test environment](#test-environment)
- [Running the tests](#running-the-tests)
- [The library](#the-library)
- [How this compares](#how-this-compares)
- [Scope](#scope)

## The scripts

| Script | Category | What it does |
| --- | --- | --- |
| [`opcua-discover`](#opcua-discover) | `discovery`, `safe`, `default` | Endpoints, security modes and policies, user tokens, certificate analysis, security findings, lateral discovery |
| [`opcua-info`](#opcua-info) | `discovery`, `intrusive` | Opens a session and reads BuildInfo, ServerStatus, namespaces, service level and RBAC state |
| [`opcua-browse`](#opcua-browse) | `discovery`, `intrusive` | Walks the address space and reports what the session may write or execute |
| [`opcua-brute`](#opcua-brute) | `brute`, `intrusive` | Password guessing against the UserName identity token |
| [`broadcast-opcua-discover`](#broadcast-opcua-discover) | `broadcast`, `discovery`, `safe` | Finds servers over multicast DNS, without scanning a single port |

They share one library, `opcua.lua`, which holds the entire protocol
implementation. The split follows Nmap's categories rather than convenience:
only `opcua-discover` is `safe`, because it never opens a session, so a routine
`-sC` scan of a plant network cannot create sessions or attempt logins.

**Everything is read-only.** The scripts never write a value and never call a
method — a writable node is proven from its AccessLevel attribute, not by
writing to it.

## Installation

```bash
sudo cp opcua.lua /usr/share/nmap/nselib/
sudo cp opcua-*.nse /usr/share/nmap/scripts/
sudo nmap --script-updatedb

nmap -p 4840 --script opcua-discover <target>
```

<details>
<summary>Running from the checkout without installing</summary>

The scripts can be given by path, but the library has to be findable. Point
`NMAPDIR` at a directory that contains it:

```bash
mkdir -p /tmp/nsedev/nselib
ln -s "$PWD/opcua.lua" /tmp/nsedev/nselib/opcua.lua
NMAPDIR=/tmp/nsedev nmap -p 4840 --script ./opcua-discover.nse <target>
```
</details>

Common invocations:

```bash
nmap -p 4840 --script opcua-discover <target>              # discovery only
nmap -p 4840 --script "opcua-* and not brute" <target>     # everything but password guessing
nmap -p 4840 -sC <target>                                  # opcua-discover runs by default
nmap -p 4840 --script opcua-discover --script-args newtargets <target>
```

## opcua-discover

Performs the connection handshake, opens a secure channel with SecurityPolicy
None and calls the discovery services that OPC 10000-4 explicitly allows
without a session.

### What it checks

**Endpoint configuration**

| Finding | Severity |
| --- | --- |
| UserName token over SecurityPolicy `None` on an unencrypted endpoint — passwords in cleartext | `CRITICAL` |
| SecurityMode `None` | `HIGH` |
| SecurityPolicy `None` | `HIGH` |
| Anonymous identity token accepted | `HIGH` |
| No endpoint at all combining SignAndEncrypt with a current policy | `HIGH` |
| Deprecated `Basic128Rsa15` or `Basic256` (SHA-1, deprecated in OPC UA 1.04) | `MEDIUM` |
| Weak certificate on an endpoint that advertises signing or encryption | `MEDIUM` |
| SecurityMode `Sign` only — authenticated but readable in transit | `LOW` |
| `SecurityLevel 0` — the server's own admission that an endpoint offers nothing | `LOW` |

**Application certificate**, parsed from the DER blob in the EndpointDescription:

- self-signed, expired, or not yet valid
- RSA keys below 2048 bits, MD5 or SHA-1 signatures
- the subjectAltName URI not matching the announced ApplicationUri, which
  OPC 10000-4 requires
- SHA-256 fingerprints correlated across every host in the scan, so a vendor
  shipping identical key material on many devices shows up in a post-scan
  summary:

```
Post-scan script results:
| opcua-discover:
|   Shared server certificates:
|_    967B2C24009A8F74... used by 2 hosts: 192.0.2.10:62541, 192.0.2.11:48010 (UaServer@opcua-nse-shared, OPC UA NSE Test Lab, DE)
```

**Lateral discovery**

- `FindServers` reveals further applications and their discovery URLs, on other
  hosts and ports as well. With `--script-args newtargets` those hosts are added
  to the scan queue.
- `FindServersOnNetwork` returns the registration cache of a Local Discovery
  Server with multicast extension.

**Rejected handshakes still count.** A server that answers `ERR` has understood
the message, so it is identified anyway:

```
| opcua-discover:
|   Protocol: OPC UA Binary (opc.tcp)
|   Status: confirmed by protocol error response
|_  Server response: server rejected HEL: Bad_TcpEndpointUrlInvalid (0x80830000) - The endpoint URL is not supported by this server.
```

### Arguments

| Argument | Default | Meaning |
| --- | --- | --- |
| `opcua-discover.timeout` | from the timing template | Socket timeout in milliseconds |
| `opcua-discover.endpoint-url` | derived from the target | Endpoint URL to request |
| `opcua-discover.discovery-paths` | `true` | Also try `/discovery` and `/UADiscovery` |
| `opcua-discover.find-servers` | `true` | Call FindServers and FindServersOnNetwork |
| `opcua-discover.certs` | `true` | Show the parsed certificate |
| `opcua-discover.recv-buffer` | `65535` | ReceiveBufferSize to advertise; lower values force chunked replies |
| `opcua-discover.all-ports` | off | Try every open TCP port, not just the known OPC UA ports |
| `opcua-discover.vulns` | off | Also report findings through Nmap's `vulns` library |
| `newtargets` | off | Add discovered hosts to the scan queue |

## opcua-info

Creates a session and reads the Server object. This is the only way to learn the
stack version over the network, and it feeds Nmap's version detection with
product, version and a derived CPE.

```console
$ nmap -p 4840 --script opcua-info 192.0.2.10

| opcua-info:
|   Session: anonymous on opc.tcp://192.0.2.10:4840/nse/ (SecurityMode None)
|   Build Information:
|     Manufacturer: FreeOpcUa
|     Product: FreeOpcUa Python Server
|     Product URI: urn:freeopcua.github.io:python:server
|     Software Version: 1.0pre
|     Build Number: 0
|   Server Status:
|     State: Running
|     Started: 2026-08-24 13:11:41Z
|     Server time: 2026-08-24 13:12:12Z (clock skew -1s)
|   Namespaces:
|     0: http://opcfoundation.org/UA/
|     1: urn:opcua-nse:test:insecure
|     2: http://opcua-nse.test/plant
|   Service Level: 255/255
|   Diagnostics:
|     Sessions: 1 open, 21 since start
|     Rejected sessions: 2 rejected, 0 on security grounds
|_  Role based access control: 14 roles: Anonymous, AuthenticatedUser, Observer, Operator, Engineer, Supervisor, ...
```

The session counters come from the server's own ServerDiagnosticsSummary: how
many clients are connected right now, how many have been since it started, and
how many it turned away. On an assessment that answers the question of whether
anyone else has been here.

The namespace URIs identify vendor and device model, the clock skew is worth
knowing before reading timestamps, and a missing `RoleSet` node means the server
predates the role model introduced in OPC UA 1.04.

A server that enforces access control is reported as such rather than producing
an empty result — the difference between "found nothing" and "the server is
doing it right":

```
|   Session: anonymous on opc.tcp://192.0.2.10:4897/nse/ (SecurityMode None)
|_  Reads denied: service fault: Bad_SecurityChecksFailed (0x801F0000) -- the session is not authorised to read the Server object; access control is enforced
```

Arguments: `username`, `password`, `timeout`, `endpoint-url`.

## opcua-browse

Walks the address space breadth first and reads AccessLevel, UserAccessLevel,
Executable and UserExecutable. UserAccessLevel is what the *current* session may
do, so a variable listed here is writable by whoever can reach the port.

```console
$ nmap -p 4840 --script opcua-browse --script-args opcua-browse.depth=2 192.0.2.10

| opcua-browse:
|   Session: anonymous (SecurityMode None)
|   Address space: 40 nodes visited, depth 2
|   Writable by this session (3):
|     ns=2;i=2 Plant/Temperature read+write
|     ns=2;i=3 Plant/Pressure read+write
|     ns=2;i=4 Plant/Setpoint read+write
|   Methods callable by this session (6):
|     ns=2;i=7 Multiply
|     i=11492 Server/GetMonitoredItems
|_  Finding: HIGH: an anonymous session can write 3 variable(s); anyone able to reach this port can change process data.
```

On a plant this is the difference between an information leak and a control
problem. The script establishes it from the access level bits alone — it never
writes and never calls.

Arguments: `depth` (default 3), `max-nodes` (default 200), `root` (default 85,
the Objects folder), `tree`, `username`, `password`, `timeout`.

## opcua-brute

Guesses UserName credentials through ActivateSession, built on Nmap's `brute`
library, so the usual `userdb`, `passdb` and `brute.*` arguments apply.

```console
$ nmap -p 4840 --script opcua-brute --script-args userdb=users.txt,passdb=pass.txt 192.0.2.10

| opcua-brute:
|   Accounts:
|     operator:operator - Valid credentials
|     engineer:Password1 - Valid credentials
|   Statistics: Performed 8 guesses in 1 seconds, average tps: 8.0
|_  Note: this endpoint accepts UserName tokens over SecurityPolicy None, so passwords are transmitted in cleartext
```

The script needs an endpoint whose UserName token policy is `None`, because any
other policy requires the password to be encrypted with the server's public key.
That restriction is itself the finding: if the script can run at all, the server
accepts passwords in cleartext.

## broadcast-opcua-discover

OPC 10000-12 has every host with OPC UA applications run a Local Discovery
Server with the multicast extension, announcing its servers as
`_opcua-tcp._tcp.local`. One multicast query then maps a segment that a port
scan would take minutes to cover — including servers on ports nobody would
think to scan.

```console
$ nmap --script broadcast-opcua-discover --script-args newtargets -sn

Pre-scan script results:
| broadcast-opcua-discover:
|   192.0.2.10:
|     Discovery URL: opc.tcp://192.0.2.10:4840/nse/
|     Capabilities: LDS,DA
|_    Added to scan queue: 192.0.2.10
```

It runs as a prerule, so with `newtargets` the hosts it finds are scanned in the
same invocation.

## Service probe for -sV

Nmap has no OPC UA probe, so `-sV` cannot identify these servers — which matters
because they mostly listen on vendor ports (49320 KEPServerEX, 53530 Prosys,
62541 OPC Foundation stack). `nmap-service-probes.opcua` adds one:

```bash
cat /usr/share/nmap/nmap-service-probes nmap-service-probes.opcua > /tmp/probes
nmap -sV --versiondb /tmp/probes -p 4840,49320,53530,62541 <target>
```

```
PORT      STATE SERVICE   VERSION
48010/tcp open  opcua-tcp OPC UA Binary Protocol
```

The probe sends a well formed HEL message. Both an `ACKF` and an `ERRF` reply
identify the protocol, because a server that rejects the endpoint URL has still
understood the message — and the rejection reason is reported too:

```
4845/tcp open  opcua-tcp OPC UA Binary Protocol (endpoint URL rejected)
```

An upstream pull request for OPC UA detection already exists
([nmap/nmap#2791](https://github.com/nmap/nmap/pull/2791), open since March
2024). Until it lands, this file is how you get the detection locally.

## Ports

The scripts run on 4840, 4843, 4845, 4855, 4885, 4897, 26543, 48010–48050,
49320, 49380, 51210, 53530 and 62541, and on any port whose service name is
`opcua-tcp`, `opc-ua-tcp`, `opcua` or `opcua-tls`. Add
`--script-args opcua-discover.all-ports` to try every open port instead.

## Test environment

`test-server/` holds a docker-compose matrix that reproduces every case the
scripts claim to detect, across three independent OPC UA implementations —
asyncua (Python), open62541 (C) and node-opcua (JavaScript). It is what the CI
integration job runs against.

| Port | Mode | What it exercises |
| --- | --- | --- |
| 4840 | `insecure` | SecurityPolicy None, anonymous full access, writable nodes, valid credentials for the brute script |
| 4843 | `lds` | An open62541 Local Discovery Server with the multicast extension — the only kind of server that answers `FindServersOnNetwork` |
| 4845 | `fault` | Answers every handshake with `ERR`, so the error path stays covered |
| 26543, 48040, 48050, 49320, 49380, 51210, 53530 | `hostile` | Completes the handshake and then lies: four-billion-element arrays, negative lengths, endless chunks, truncated messages, unknown chunk types, a 2 GB string, a byte every two seconds |
| 4855 | `secure` | Seven endpoints across all modern policies, valid 2048 bit certificate — also the chunking case |
| 4885 | `legacy` | Basic128Rsa15 and Basic256 with a 1024 bit SHA-1 certificate whose URI does not match |
| 4897 | `expired` | Expired certificate, and anonymous sessions denied read access |
| 48010, 62541 | `shared-a`, `shared-b` | The same certificate on two hosts, for fingerprint correlation |
| 48020 | `open62541` | A second implementation, in C: string NodeIds, GUID authentication tokens, its own encoding choices |
| 48030 | `node-opcua` | A third implementation, in JavaScript |

```bash
cd test-server
pip install cryptography
python3 gen_certs.py          # certificates, including deliberately broken ones
docker compose up -d --build
```

See [test-server/README.md](test-server/README.md) for the details.

## Running the tests

```bash
./test/run-tests.sh --unit    # library unit tests only, no docker, no network
./test/run-tests.sh           # unit tests plus integration against the matrix
```

```
== opcua-discover against the secure server (port 4855) ==
  PASS  all seven endpoints decoded
  PASS  modern policy recognised
  PASS  certificate parsed
  PASS  SAN URI matches ApplicationUri
  ...
== Summary ==
  57 passed, 0 failed
```

The 50 unit tests live inside `opcua.lua` and run through Nmap's own framework,
against byte fixtures rather than a live server:

```bash
nmap --script unittest --script-args "unittest.run,unittest.tests={opcua}"
```

CI runs three jobs on every push — unit tests, shellcheck, and the full
integration suite against the container matrix. See
[`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## The library

`opcua.lua` is a self-contained OPC UA client for NSE, usable on its own:

```lua
local opcua = require "opcua"

local conn = opcua.Connection:new(host, port)
conn:connect()                       -- TCP plus HEL/ACK with buffer negotiation
conn:open_secure_channel()           -- SecurityPolicy None
local endpoints = conn:get_endpoints()
local findings = opcua.assess_endpoints(endpoints)
conn:close()
```

What it covers:

- **Transport** — HEL/ACK/ERR with negotiated limits, decoded status codes,
  chunk assembly for `C`, `F` and `A` chunks, sending chunked requests
- **Binary encoding** — a cursor object for every built-in type, including NodeId
  in all five encodings, ExpandedNodeId, Variant with arrays, DataValue,
  ExtensionObject, DiagnosticInfo and DateTime as Windows FILETIME
- **Services** — OpenSecureChannel, GetEndpoints, FindServers,
  FindServersOnNetwork, CreateSession, ActivateSession, Read, Browse,
  CloseSecureChannel
- **Assessment** — policy ratings, endpoint findings, and certificate analysis
  through `sslcert.parse_ssl_certificate`, which digests the raw DER directly

## How this compares

| | ot-blue-team | msf-opcua | opcua-scan | OpalOPC | this |
| --- | :-: | :-: | :-: | :-: | :-: |
| HEL/ACK detection | yes | yes | yes | yes | yes |
| ERR status decoding | no | no | no | no | yes |
| Chunk reassembly | no | yes | yes | yes | yes |
| GetEndpoints | no | yes | yes | yes | yes |
| FindServers, new targets | no | no | yes | yes | yes |
| Certificate analysis | no | no | no | yes | yes |
| Cross-host certificate correlation | no | no | no | no | yes |
| Session, BuildInfo, CPE | no | yes | yes | yes | yes |
| Access level audit | no | yes | yes | yes | yes |
| Credential guessing | no | yes | partly | yes | yes |
| Writes to the target | no | no | yes | no | **no, by design** |
| Runs natively in Nmap | yes | no | no | no | yes |

The comparison targets are [ot-nmap-blue-team](https://github.com/carbon-evolution/ot-nmap-blue-team),
[COMSYS/msf-opcua](https://github.com/COMSYS/msf-opcua),
[wavestone-cdt/opcua-scan](https://github.com/wavestone-cdt/opcua-scan) and
[OpalOPC](https://opalopc.com/).

## Scope

These scripts are for authorised assessments and asset inventory. Only scan
systems you have permission to scan.

They are read-only by design: `Write` and `Call` are deliberately not
implemented, because in a plant a written setpoint is an incident, not a test
result. Writable nodes and callable methods are reported from their attributes.

A scanner points itself at unknown ports, so the peer may answer with anything.
The library caps what it will accept — 512 chunks and 8 MB per reassembled
message, strict array and string lengths — and the test suite attacks it with
seven hostile answers to prove each one is refused within a time budget rather
than believed.

Why it matters: an internet-wide measurement of 1 114 reachable OPC UA
deployments found 92 % configured deficiently — 26 % with security disabled,
25 % on deprecated cryptography, 44 % allowing anonymous access
([Dahlmanns et al., ACM IMC 2020](https://arxiv.org/pdf/2010.13539)). Almost all
of it is visible without a single login.

## License

Same as Nmap — see <https://nmap.org/book/man-legal.html>.
