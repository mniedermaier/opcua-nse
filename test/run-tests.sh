#!/usr/bin/env bash
#
# Test suite for the OPC UA NSE scripts.
#
#   ./test/run-tests.sh            unit tests, then integration against the
#                                  docker-compose test matrix
#   ./test/run-tests.sh --unit     unit tests only (no docker, no network)
#
# The scripts are exercised through a throwaway NMAPDIR so nothing has to be
# installed into /usr/share/nmap.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/nselib"
ln -sf "$REPO/opcua.lua" "$WORK/nselib/opcua.lua"
export NMAPDIR="$WORK"

# The matrix is reached on the loopback address by default. Port 4840 in
# particular is often already taken on an engineering workstation - a CODESYS
# runtime, a vendor gateway - and a foreign server there would silently answer
# the tests. When that happens the suite falls back to the container's own
# address instead of demanding that the other server be shut down.
HOST="${OPCUA_TEST_HOST:-127.0.0.1}"

declare -A CONTAINER_FOR_PORT=(
  [4840]=opcua-test-insecure   [4845]=opcua-test-fault
  [4855]=opcua-test-secure     [4885]=opcua-test-legacy
  [4897]=opcua-test-expired    [48010]=opcua-test-shared-a
  [48020]=opcua-test-open62541 [48030]=opcua-test-node
  [62541]=opcua-test-shared-b
  [4843]=opcua-test-lds
  [26543]=opcua-test-hostile   [48040]=opcua-test-hostile
  [48050]=opcua-test-hostile   [49320]=opcua-test-hostile
  [49380]=opcua-test-hostile   [51210]=opcua-test-hostile
  [53530]=opcua-test-hostile
)

# port -> attack, and how long the scripts may take to give up on it
declare -A HOSTILE_ATTACK=(
  [26543]="huge-array"      [48040]="endless-chunks"
  [48050]="truncated"       [49320]="negative-length"
  [49380]="bad-chunk-type"  [51210]="giant-string"
  [53530]="slow-drip"
)
declare -A HOST_FOR_PORT

PASS=0
FAIL=0
SKIP=0
UNIT_ONLY=0
[[ "${1:-}" == "--unit" ]] && UNIT_ONLY=1

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
head2() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }

# check <description> <file-with-output> <pattern>
check() {
  local description="$1" file="$2" pattern="$3"
  if grep -qE "$pattern" "$file"; then
    green "  PASS  $description"
    PASS=$((PASS + 1))
  else
    red   "  FAIL  $description"
    red   "        expected pattern: $pattern"
    red   "        actual output:"
    sed 's/^/          /' "$file" | tail -20 >&2
    FAIL=$((FAIL + 1))
  fi
}

# An open TCP port does not mean the OPC UA stack behind it is ready: the
# servers accept connections seconds before they answer GetEndpoints. Wait for
# a real protocol answer instead.
# wait_for_opcua <port> [attempts]
wait_for_opcua() {
  local port="$1" host="$2" attempts="${3:-40}" i out
  out="$WORK/ready-$port.txt"
  for ((i = 1; i <= attempts; i++)); do
    timeout 15 nmap -p "$port" --script "$REPO/opcua-discover.nse" "$host" \
      > "$out" 2>/dev/null
    # The fault server only ever answers with an error, which still identifies it.
    if grep -qE "confirmed by protocol error" "$out"; then
      return 0
    fi
    if grep -q "urn:opcua-nse:test:" "$out"; then
      return 0
    fi
    if grep -q "Endpoints (" "$out"; then
      # Something speaks OPC UA here, but it is not one of ours.
      return 2
    fi
    sleep 2
  done
  return 1
}

# Returns the address the given matrix port answers on, preferring the
# loopback address and falling back to the container's own IP.
container_ip() {
  docker inspect "$1" \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null
}

resolve_port_host() {
  local port="$1" status ip
  HOST_FOR_PORT[$port]="$HOST"
  wait_for_opcua "$port" "$HOST"
  status=$?
  if [[ $status -eq 0 ]]; then
    return 0
  fi

  if [[ $status -eq 2 ]]; then
    printf '  note   port %s on %s is a foreign OPC UA server:\n' "$port" "$HOST"
    grep -E "Application (Name|URI)" "$WORK/ready-$port.txt" | head -2 | sed 's/^/           /'
  fi

  ip="$(container_ip "${CONTAINER_FOR_PORT[$port]}")"
  if [[ -n "$ip" ]] && wait_for_opcua "$port" "$ip" 10; then
    HOST_FOR_PORT[$port]="$ip"
    printf '         using the container address %s instead\n' "$ip"
    return 0
  fi
  return 1
}

# scan <output-file> <script> <port> [extra nmap args...]
scan() {
  local out="$1" script="$2" port="$3"; shift 3
  timeout 120 nmap -p "$port" --script "$REPO/$script" "$@" \
    "${HOST_FOR_PORT[$port]:-$HOST}" > "$out" 2>&1
}

head2 "Environment"
nmap --version | head -2 | sed 's/^/  /'
echo "  repository: $REPO"

head2 "Lua syntax"
if command -v luac5.4 >/dev/null 2>&1 || command -v luac >/dev/null 2>&1; then
  LUAC="$(command -v luac5.4 || command -v luac)"
  for f in "$REPO"/opcua.lua "$REPO"/*.nse; do
    if "$LUAC" -p "$f" 2>/dev/null; then
      green "  PASS  $(basename "$f") parses"
      PASS=$((PASS + 1))
    else
      red "  FAIL  $(basename "$f") does not parse"
      "$LUAC" -p "$f"
      FAIL=$((FAIL + 1))
    fi
  done
else
  echo "  SKIP  no luac available; NSE will parse the files anyway"
fi

head2 "Script metadata"
META="$WORK/meta.txt"
nmap --script-help "$REPO/opcua-discover.nse,$REPO/opcua-info.nse,$REPO/opcua-browse.nse,$REPO/opcua-brute.nse" > "$META" 2>&1
for s in opcua-discover opcua-info opcua-browse opcua-brute; do
  check "$s is loadable and documented" "$META" "^$s"
done

head2 "Unit tests"
UNIT="$WORK/unit.txt"
UNITTEST_SCRIPT="unittest"
for candidate in /usr/share/nmap/scripts/unittest.nse \
                 /usr/local/share/nmap/scripts/unittest.nse; do
  [[ -f "$candidate" ]] && UNITTEST_SCRIPT="$candidate" && break
done
nmap --script "$UNITTEST_SCRIPT" \
     --script-args "unittest.run,unittest.tests={opcua}" -d1 > "$UNIT" 2>&1
grep -E "tests passed" "$UNIT" | sed 's/^/  /'
check "all library unit tests pass" "$UNIT" "All tests passed"

if [[ $UNIT_ONLY -eq 1 ]]; then
  head2 "Summary"
  echo "  $PASS passed, $FAIL failed (unit only)"
  [[ $FAIL -eq 0 ]] || exit 1
  exit 0
fi

head2 "Test matrix"
if ! docker compose -f "$REPO/test-server/docker-compose.yml" ps --status running \
     --format '{{.Name}}' 2>/dev/null | grep -q opcua-test; then
  echo "  starting containers"
  [[ -f "$REPO/test-server/certs/server_ok_cert.pem" ]] || \
    (cd "$REPO/test-server" && python3 gen_certs.py)
  docker compose -f "$REPO/test-server/docker-compose.yml" up -d --build >/dev/null 2>&1
  sleep 10
fi
docker compose -f "$REPO/test-server/docker-compose.yml" ps \
  --format '  {{.Name}} {{.Status}}' 2>/dev/null

echo "  waiting for the servers to answer OPC UA"
for port in 4840 4843 4845 4855 4885 4897 48010 48020 48030 62541; do
  if resolve_port_host "$port"; then
    green "  ready  port $port"
  else
    red   "  FAIL   port $port did not answer as one of the test servers"
    FAIL=$((FAIL + 1))
  fi
done

head2 "opcua-discover against the insecure server (port 4840)"
OUT="$WORK/discover-insecure.txt"
scan "$OUT" opcua-discover.nse 4840
check "service is confirmed"            "$OUT" "OPC UA Binary"
check "transport parameters reported"   "$OUT" "protocol version 0, receive buffer"
check "application name decoded"        "$OUT" "Application Name: OPC UA Test Server"
check "endpoint listed"                 "$OUT" "Security: None / None"
check "both token types decoded"        "$OUT" "Anonymous.*UserName"
check "SecurityMode None reported"      "$OUT" "HIGH: SecurityMode None"
check "cleartext credentials reported"  "$OUT" "CRITICAL: Credentials sent in cleartext"
check "anonymous access reported"       "$OUT" "HIGH: Anonymous access allowed"
check "FindServers answered"            "$OUT" "Known Servers"

head2 "opcua-discover against the secure server (port 4855)"
OUT="$WORK/discover-secure.txt"
scan "$OUT" opcua-discover.nse 4855
check "all seven endpoints decoded"     "$OUT" "Endpoints \(7\)"
check "modern policy recognised"        "$OUT" "SignAndEncrypt / Aes256_Sha256_RsaPss"
check "certificate parsed"              "$OUT" "Key: rsa 2048 bits, sha256WithRSAEncryption"
check "SAN URI matches ApplicationUri"  "$OUT" "ApplicationUri \(SAN\): urn:opcua-nse:test:secure"
check "self-signed noted"               "$OUT" "certificate is self-signed"
check "SHA-256 fingerprint computed"    "$OUT" "SHA-256: [0-9A-F]{64}"
check "no false 'insecure' verdict"     "$OUT" "Sign only"

head2 "Chunk reassembly (8192 byte buffer forces multiple chunks)"
OUT="$WORK/discover-chunked.txt"
scan "$OUT" opcua-discover.nse 4855 --script-args opcua-discover.recv-buffer=8192 -d2
check "server split the response"       "$OUT" "<- MSGC 8192 bytes"
check "final chunk received"            "$OUT" "<- MSGF"
check "endpoints survived reassembly"   "$OUT" "Endpoints \(7\)"

head2 "opcua-discover against the legacy server (port 4885)"
OUT="$WORK/discover-legacy.txt"
scan "$OUT" opcua-discover.nse 4885
check "Basic128Rsa15 flagged"           "$OUT" "Deprecated SecurityPolicy Basic128Rsa15"
check "Basic256 flagged"                "$OUT" "Deprecated SecurityPolicy Basic256"
check "weak key detected"               "$OUT" "weak 1024 bit RSA key"
check "weak signature detected"         "$OUT" "sha1WithRSAEncryption"
check "URI mismatch detected"           "$OUT" "certificate URI does not match ApplicationUri"

head2 "opcua-discover against the expired certificate (port 4897)"
OUT="$WORK/discover-expired.txt"
scan "$OUT" opcua-discover.nse 4897
check "expiry detected"                 "$OUT" "certificate expired on"

head2 "Certificate correlation across hosts (ports 48010 and 62541)"
OUT="$WORK/discover-shared.txt"
# Both certificate twins have to be scanned in one run for the correlation.
timeout 120 nmap -p 48010,62541 --script "$REPO/opcua-discover.nse" \
  "${HOST_FOR_PORT[48010]:-$HOST}" "${HOST_FOR_PORT[62541]:-$HOST}" > "$OUT" 2>&1
check "shared certificate reported"     "$OUT" "used by 2 hosts"

head2 "opcua-info (session, build information)"
OUT="$WORK/info.txt"
scan "$OUT" opcua-info.nse 4840
check "session established"             "$OUT" "Session: anonymous"
check "manufacturer read"               "$OUT" "Manufacturer: FreeOpcUa"
check "software version read"           "$OUT" "Software Version:"
check "server state read"               "$OUT" "State: Running"
check "namespaces listed"               "$OUT" "0: http://opcfoundation.org/UA/"
check "RBAC state determined"           "$OUT" "Role based access control"

head2 "opcua-browse (access level audit)"
OUT="$WORK/browse.txt"
scan "$OUT" opcua-browse.nse 4840 --script-args opcua-browse.depth=2
check "address space walked"            "$OUT" "nodes visited"
check "writable variables found"        "$OUT" "Writable by this session"
check "writable finding raised"         "$OUT" "HIGH: an anonymous session can write"
check "read-only node not flagged"      "$OUT" "SerialNumber \(Variable\) read$"

head2 "opcua-brute (credential guessing)"
OUT="$WORK/brute.txt"
printf 'operator\nadmin\nengineer\n' > "$WORK/users.txt"
printf 'operator\nadmin\nPassword1\n' > "$WORK/pass.txt"
scan "$OUT" opcua-brute.nse 4840 \
  --script-args "userdb=$WORK/users.txt,passdb=$WORK/pass.txt,brute.firstonly=false"
check "valid account found"             "$OUT" "operator:operator - Valid credentials"
check "second account found"            "$OUT" "engineer:Password1 - Valid credentials"
check "cleartext note emitted"          "$OUT" "passwords are transmitted in cleartext"
if grep -q "admin:.* - Valid credentials" "$OUT"; then
  red "  FAIL  invalid credentials were accepted"
  FAIL=$((FAIL + 1))
else
  green "  PASS  invalid credentials rejected"
  PASS=$((PASS + 1))
fi

head2 "node-opcua stack (port 48030)"
OUT="$WORK/discover-node.txt"
scan "$OUT" opcua-discover.nse 48030
check "endpoints decoded"               "$OUT" "Endpoints \(2\)"
check "certificate parsed"              "$OUT" "Key: rsa 2048 bits"
check "token list deduplicated"         "$OUT" "User tokens: [^,]+(, [^,]+)*$"

OUT="$WORK/info-node.txt"
scan "$OUT" opcua-info.nse 48030
check "session on a second stack"       "$OUT" "Session: anonymous"
check "build info from node-opcua"      "$OUT" "Manufacturer: node-opcua"
check "software version read"           "$OUT" "Software Version: [0-9]"
check "auditing state reported"         "$OUT" "Auditing: disabled"

OUT="$WORK/browse-node.txt"
scan "$OUT" opcua-browse.nse 48030 --script-args opcua-browse.depth=2,opcua-browse.tree=false
check "same three writable variables"   "$OUT" "Writable by this session \(3\)"
check "writable finding raised"         "$OUT" "HIGH: an anonymous session can write 3"

head2 "open62541 stack (port 48020)"
OUT="$WORK/discover-open62541.txt"
scan "$OUT" opcua-discover.nse 48020
check "endpoints decoded"               "$OUT" "Security: None / None"
check "both discovery URLs decoded"     "$OUT" "Discovery URLs"
check "endpoint listed once per finding" "$OUT" "Anonymous access allowed \(endpoint 1\)"

OUT="$WORK/info-open62541.txt"
scan "$OUT" opcua-info.nse 48020
# open62541 hands out a GUID AuthenticationToken; writing it back verbatim is
# what keeps the session alive through ActivateSession.
check "session survives a GUID token"   "$OUT" "Session: anonymous"
check "build info from open62541"       "$OUT" "Manufacturer: open62541"
check "server state read"               "$OUT" "State: Running"
# ServerDiagnosticsSummary is optional; open62541 and node-opcua keep it,
# asyncua does not.
check "session counters read"           "$OUT" "Sessions: [0-9]+ open, [0-9]+ since start"

OUT="$WORK/browse-open62541.txt"
scan "$OUT" opcua-browse.nse 48020 --script-args opcua-browse.depth=2,opcua-browse.tree=false
check "string NodeIds handled"          "$OUT" "ns=1;s=Temperature"
check "same three writable variables"   "$OUT" "Writable by this session \(3\)"

head2 "Hostile answers"
# The hostile server speaks the handshake correctly and only then lies. Every
# attack must be refused quickly, with a message naming the problem, and
# without the script erroring out.
resolve_hostile_host() {
  local port="$1" ip
  HOST_FOR_PORT[$port]="$HOST"
  if timeout 2 bash -c "</dev/tcp/$HOST/$port" 2>/dev/null; then
    return 0
  fi
  ip="$(container_ip "${CONTAINER_FOR_PORT[$port]}")"
  if [[ -n "$ip" ]] && timeout 2 bash -c "</dev/tcp/$ip/$port" 2>/dev/null; then
    HOST_FOR_PORT[$port]="$ip"
    return 0
  fi
  return 1
}

# The slowest attack drips one byte every two seconds, so allow for the socket
# timeout; everything else has to be over in a few seconds.
declare -A HOSTILE_BUDGET=([53530]=40 [48040]=25)

for hostile_port in 26543 48040 48050 49320 49380 51210 53530; do
  attack="${HOSTILE_ATTACK[$hostile_port]}"
  if ! resolve_hostile_host "$hostile_port"; then
    red "  FAIL  $attack: port $hostile_port is not reachable"
    FAIL=$((FAIL + 1))
    continue
  fi

  budget="${HOSTILE_BUDGET[$hostile_port]:-15}"
  OUT="$WORK/hostile-$attack.txt"
  started=$(date +%s)
  scan "$OUT" opcua-discover.nse "$hostile_port"
  elapsed=$(( $(date +%s) - started ))

  if grep -q "ERROR: Script execution failed" "$OUT"; then
    red "  FAIL  $attack: the script threw an error"
    FAIL=$((FAIL + 1))
  elif [[ $elapsed -gt $budget ]]; then
    red "  FAIL  $attack: took ${elapsed}s, budget was ${budget}s"
    FAIL=$((FAIL + 1))
  elif ! grep -qE "none returned|confirmed by protocol error|OPC UA confirmed" "$OUT"; then
    red "  FAIL  $attack: no verdict in the output"
    sed 's/^/          /' "$OUT" | tail -12 >&2
    FAIL=$((FAIL + 1))
  else
    green "  PASS  $attack refused in ${elapsed}s"
    PASS=$((PASS + 1))
  fi
done

# The two that were actually dangerous get their message checked as well.
check "endless chunks are cut off"      "$WORK/hostile-endless-chunks.txt" \
  "aborted after 512 chunks"
check "a bogus array length is named"   "$WORK/hostile-huge-array.txt" \
  "invalid array length -6"
check "a bogus string length is named"  "$WORK/hostile-negative-length.txt" \
  "invalid string length -2"
check "an unknown chunk type is named"  "$WORK/hostile-bad-chunk-type.txt" \
  "unknown chunk type"

head2 "ERR handshake (port 4845 rejects every HEL)"
OUT="$WORK/discover-fault.txt"
scan "$OUT" opcua-discover.nse 4845
check "service still identified"        "$OUT" "Protocol: OPC UA Binary"
check "rejection reported as such"      "$OUT" "confirmed by protocol error response"
check "status code decoded"             "$OUT" "Bad_TcpEndpointUrlInvalid \(0x80830000\)"
check "reason string decoded"           "$OUT" "The endpoint URL is not supported"

head2 "vulns library integration"
OUT="$WORK/discover-vulns.txt"
scan "$OUT" opcua-discover.nse 4885 --script-args opcua-discover.vulns
check "vulnerability report rendered"   "$OUT" "state: VULNERABLE"
check "risk factors assigned"           "$OUT" "Vulnerabilities"

head2 "Access control enforced (port 4897 denies anonymous reads)"
OUT="$WORK/info-denied.txt"
scan "$OUT" opcua-info.nse 4897
check "session still established"       "$OUT" "Session: anonymous"
check "denied reads reported"           "$OUT" "Reads denied.*access control is enforced"

OUT="$WORK/browse-denied.txt"
scan "$OUT" opcua-browse.nse 4897
check "denied browse reported"          "$OUT" "not readable.*access control is enforced"
if grep -q "Writable by this session" "$WORK/browse-denied.txt"; then
  red "  FAIL  writable nodes reported although browsing was denied"
  FAIL=$((FAIL + 1))
else
  green "  PASS  no writable nodes claimed when browsing is denied"
  PASS=$((PASS + 1))
fi

head2 "Local Discovery Server (port 4843)"
OUT="$WORK/discover-lds.txt"
scan "$OUT" opcua-discover.nse 4843
check "application type decoded"        "$OUT" "Application Type: DiscoveryServer"
# Only an LDS with the multicast extension answers this service at all.
check "FindServersOnNetwork answered"   "$OUT" "Local Discovery Server Registrations"
check "announced capabilities decoded"  "$OUT" "\[LDS\]"

head2 "Multicast discovery"
# Needs multicast to reach the responder, which not every environment allows.
# A missing answer is reported as skipped rather than failed.
OUT="$WORK/broadcast.txt"
timeout 60 nmap --script "$REPO/broadcast-opcua-discover.nse" > "$OUT" 2>&1
if grep -q "Discovery URL: opc.tcp://" "$OUT"; then
  green "  PASS  the announced server was found over mDNS"
  PASS=$((PASS + 1))
  check "capabilities decoded"          "$OUT" "Capabilities: LDS,DA"
else
  yellow "  SKIP  no mDNS answer; multicast is not available here"
  SKIP=$((SKIP + 1))
fi

head2 "Service probe"
OUT="$WORK/version.txt"
cat /usr/share/nmap/nmap-service-probes "$REPO/nmap-service-probes.opcua" > "$WORK/probes"
# Each port may live on its own address, so scan them one at a time. 4845 only
# ever answers with an error, which the probe has to recognise as well.
: > "$OUT"
for probe_port in 4840 4845 4855 48010; do
  timeout 60 nmap -sV --versiondb "$WORK/probes" --version-intensity 9 \
    -p "$probe_port" "${HOST_FOR_PORT[$probe_port]:-$HOST}" >> "$OUT" 2>&1
done
check "version detection identifies OPC UA" "$OUT" "OPC UA Binary Protocol"
check "identified on a vendor port"         "$OUT" "48010/tcp open .*OPC UA Binary Protocol"
check "a rejection is identified too"       "$OUT" "4845/tcp open .*endpoint URL rejected"

head2 "Summary"
if [[ $SKIP -gt 0 ]]; then
  echo "  $PASS passed, $FAIL failed, $SKIP skipped"
else
  echo "  $PASS passed, $FAIL failed"
fi
[[ $FAIL -eq 0 ]] || exit 1
