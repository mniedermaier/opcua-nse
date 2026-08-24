local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"
local vulns = require "vulns"
local opcua = require "opcua"

description = [[
Discovers OPC UA (IEC 62541) servers and enumerates their endpoints, security
configuration and application certificates.

The script performs the OPC UA Connection Protocol handshake (HEL/ACK), opens a
secure channel with SecurityPolicy None and calls the discovery services that
the specification explicitly allows without a session:

* <code>GetEndpoints</code> - endpoint URLs, security modes and policies, accepted
  user identity tokens, transport profiles and the server's application description
* <code>FindServers</code> - further OPC UA applications known to the server,
  including discovery URLs on other hosts
* <code>FindServersOnNetwork</code> - the registration cache of a Local Discovery
  Server with multicast extension

Each endpoint is rated: SecurityMode None, SecurityPolicy None, the deprecated
SHA-1 policies Basic128Rsa15 and Basic256, anonymous access and UserName tokens
that would travel in cleartext are reported as findings. The DER encoded server
certificate is parsed to check for self-signed, expired, weak-key and weak-hash
certificates and for the ApplicationUri/subjectAltName mismatch required by
OPC 10000-4. Certificate fingerprints are correlated across all scanned hosts,
which reveals vendors shipping the same key material on many devices.

No session is created and nothing is written, so the script is read-only.
]]

---
-- @usage
-- nmap -p 4840 --script opcua-discover <target>
-- nmap -sV --script opcua-discover <target>
-- nmap -p 4840 --script opcua-discover --script-args newtargets <target>
--
-- @output
-- PORT     STATE SERVICE
-- 4840/tcp open  opcua-tcp
-- | opcua-discover:
-- |   Protocol: OPC UA Binary (opc.tcp)
-- |   Transport: protocol version 0, receive buffer 65535, send buffer 65535
-- |   Server:
-- |     Application Name: OPC UA Test Server
-- |     Application URI: urn:freeopcua:test:server
-- |     Product URI: urn:freeopcua.github.io:server
-- |     Application Type: Server
-- |   Endpoints (2):
-- |     1:
-- |       URL: opc.tcp://192.0.2.10:4840/freeopcua/server/
-- |       Security: None / None (level 0)
-- |       User tokens: Anonymous, UserName [None]
-- |     2:
-- |       URL: opc.tcp://192.0.2.10:4840/freeopcua/server/
-- |       Security: SignAndEncrypt / Basic256Sha256 (level 3)
-- |       User tokens: Anonymous, UserName [Basic256Sha256]
-- |   Server Certificate:
-- |     Subject: UaServer@host, Test Org
-- |     Issuer: UaServer@host, Test Org
-- |     Valid: 2025-01-01 00:00:00 UTC - 2026-01-01 00:00:00 UTC
-- |     Key: rsa 2048 bits, sha256WithRSAEncryption
-- |     ApplicationUri (SAN): urn:freeopcua:test:server
-- |     SHA-256: 3A7B...
-- |   Security Findings:
-- |     CRITICAL: Credentials sent in cleartext (endpoint 1)
-- |     HIGH: SecurityMode None (endpoint 1)
-- |     HIGH: Anonymous access allowed (endpoints 1, 2)
-- |_    MEDIUM: Deprecated SecurityPolicy Basic256 (endpoint 3)
--
-- @xmloutput
-- <elem key="protocol">OPC UA Binary (opc.tcp)</elem>
-- <table key="server">
--   <elem key="application_name">OPC UA Test Server</elem>
--   <elem key="application_uri">urn:freeopcua:test:server</elem>
-- </table>
-- <table key="endpoints">
--   <table>
--     <elem key="url">opc.tcp://192.0.2.10:4840/</elem>
--     <elem key="security_mode">None</elem>
--     <elem key="security_policy">None</elem>
--   </table>
-- </table>
--
-- @args opcua-discover.timeout Socket timeout in milliseconds. Default: derived
--       from the Nmap timing template.
-- @args opcua-discover.endpoint-url Endpoint URL to request instead of the
--       one built from the target address.
-- @args opcua-discover.discovery-paths Also try the common discovery paths
--       (/discovery, /UADiscovery) when the root URL returns no endpoints.
--       Default: true
-- @args opcua-discover.find-servers Call FindServers and FindServersOnNetwork.
--       Default: true
-- @args opcua-discover.certs Show the parsed server certificate. Default: true
-- @args opcua-discover.recv-buffer ReceiveBufferSize to advertise in the HEL
--       message (minimum 8192). Lower values force the server to split its
--       replies into several chunks. Default: 65535
-- @args opcua-discover.all-ports Try every open TCP port, not just the known
--       OPC UA ports. Useful while Nmap has no OPC UA service probe.
-- @args opcua-discover.vulns Report the security findings through Nmap's vulns
--       library in addition to the plain list, so they take part in the
--       vulnerability reporting the vulns.* arguments control. Default: false
-- @args newtargets Add discovery URLs found on other hosts to the scan queue.

author = "Matthias Niedermaier"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "default"}

local known_ports = shortport.port_or_service(opcua.PORTS, opcua.SERVICES, "tcp")

portrule = function(host, port)
  if stdnse.get_script_args(SCRIPT_NAME .. ".all-ports") then
    return port.protocol == "tcp" and
           (port.state == "open" or port.state == "open|filtered")
  end
  return known_ports(host, port)
end

postrule = function()
  return nmap.registry.opcua_certs ~= nil
end

local arg_timeout = stdnse.get_script_args(SCRIPT_NAME .. ".timeout")
local arg_url = stdnse.get_script_args(SCRIPT_NAME .. ".endpoint-url")
local arg_paths = stdnse.get_script_args(SCRIPT_NAME .. ".discovery-paths")
local arg_find = stdnse.get_script_args(SCRIPT_NAME .. ".find-servers")
local arg_certs = stdnse.get_script_args(SCRIPT_NAME .. ".certs")
local arg_buffer = stdnse.get_script_args(SCRIPT_NAME .. ".recv-buffer")
local arg_vulns = stdnse.get_script_args(SCRIPT_NAME .. ".vulns")

local function enabled(value, default)
  if value == nil then return default end
  return not (value == "false" or value == "0" or value == false)
end

--- Builds the list of endpoint URLs to try, most specific first.
local function candidate_urls(host, port)
  local urls = {}
  local seen = {}
  local function add(u)
    if u and not seen[u] then
      seen[u] = true
      urls[#urls + 1] = u
    end
  end

  if arg_url then
    add(arg_url)
    return urls
  end

  local ip = host.ip
  if ip and ip:find(":", 1, true) then ip = "[" .. ip .. "]" end
  add(string.format("opc.tcp://%s:%d", ip, port.number))

  local name = host.targetname or host.name
  if name and name ~= "" then
    add(string.format("opc.tcp://%s:%d", name, port.number))
  end

  if enabled(arg_paths, true) then
    add(string.format("opc.tcp://%s:%d/discovery", ip, port.number))
    add(string.format("opc.tcp://%s:%d/UADiscovery", ip, port.number))
  end

  return urls
end

--- Formats the user identity tokens of an endpoint.
local function format_tokens(ep)
  local parts = {}
  local seen = {}
  for _, tok in ipairs(ep.user_identity_tokens or {}) do
    local policy = tok.security_policy_uri and opcua.policy_name(tok.security_policy_uri)
    local label
    if policy and policy ~= "unknown" then
      label = string.format("%s [%s]", tok.token_type, policy)
    else
      label = tok.token_type
    end
    -- Servers may list one token type several times under different policy
    -- ids; that is one offer as far as an assessment is concerned.
    if not seen[label] then
      seen[label] = true
      parts[#parts + 1] = label
    end
  end
  if #parts == 0 then return "none offered" end
  return table.concat(parts, ", ")
end

--- Records a certificate fingerprint in the registry for cross-host correlation.
local function record_certificate(host, port, cert)
  if not cert or not cert.fingerprint_sha256 then return end
  nmap.registry.opcua_certs = nmap.registry.opcua_certs or {}
  local entry = nmap.registry.opcua_certs[cert.fingerprint_sha256]
  if not entry then
    entry = {subject = cert.subject, hosts = {}}
    nmap.registry.opcua_certs[cert.fingerprint_sha256] = entry
  end
  local where = string.format("%s:%d", host.ip, port.number)
  for _, h in ipairs(entry.hosts) do
    if h == where then return end
  end
  entry.hosts[#entry.hosts + 1] = where
end

--- Feeds discovery URLs pointing at other hosts into the scan queue.
local function add_targets(host, urls, out)
  if not target.ALLOW_NEW_TARGETS then return end
  local added = {}
  for _, url in ipairs(urls or {}) do
    local hostname = opcua.discovery_url_host(url)
    if hostname and hostname ~= host.ip and hostname ~= host.targetname then
      local status = target.add(hostname)
      if status then
        added[#added + 1] = hostname
      end
    end
  end
  if #added > 0 then
    out["Added to scan queue"] = table.concat(added, ", ")
  end
end

-- Risk factors the vulns library understands, keyed by our severities.
local RISK_FACTOR = {critical = "High", high = "High", medium = "Medium",
                     low = "Low", info = "Low"}

--- Turns the findings into a vulns report, for the vulns.* reporting chain.
local function vulns_report(host, port, findings, endpoints)
  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  for _, f in ipairs(findings) do
    local extra = {}
    if #f.endpoints > 0 then
      local urls = {}
      for _, index in ipairs(f.endpoints) do
        local ep = endpoints[index]
        urls[#urls + 1] = string.format("endpoint %d: %s (%s/%s)", index,
          ep.endpoint_url or "?", ep.security_mode,
          opcua.policy_name(ep.security_policy_uri))
      end
      extra = urls
    end
    report:add_vulns({
      title = f.title,
      state = vulns.STATE.VULN,
      risk_factor = RISK_FACTOR[f.severity] or "Low",
      description = f.detail,
      extra_info = #extra > 0 and extra or nil,
      references = {
        "https://reference.opcfoundation.org/Core/Part2/v105/docs/",
      },
    })
  end
  return report:make_output()
end

--- Renders the certificate block.
local function certificate_output(cert)
  local out = stdnse.output_table()
  out["Subject"] = cert.subject
  out["Issuer"] = cert.self_signed and (cert.issuer .. " (self-signed)") or cert.issuer
  out["Valid"] = string.format("%s - %s", cert.valid_from, cert.valid_to)
  if cert.key_type then
    out["Key"] = string.format("%s %s bits, %s", cert.key_type,
      tostring(cert.key_bits), tostring(cert.sig_algorithm))
  end
  if cert.san_uri then
    out["ApplicationUri (SAN)"] = cert.san_uri
  elseif cert.subject_alt_name then
    out["Subject Alt Name"] = cert.subject_alt_name
  end
  if cert.fingerprint_sha256 then
    out["SHA-256"] = cert.fingerprint_sha256
  end
  if #cert.issues > 0 then
    local issues = {}
    for _, iss in ipairs(cert.issues) do
      issues[#issues + 1] = string.format("%s: %s", iss.severity:upper(), iss.text)
    end
    out["Issues"] = issues
  end
  return out
end

--- Runs the discovery services against an already connected server.
local function enumerate(conn, host, port, out)
  local endpoints, err
  for _, url in ipairs(candidate_urls(host, port)) do
    endpoints, err = conn:get_endpoints(url)
    if endpoints and #endpoints > 0 then
      conn.used_url = url
      break
    end
    stdnse.debug1("GetEndpoints for %s: %s", url,
      endpoints and "0 endpoints" or tostring(err))
    if not endpoints then
      -- A transport or decoding failure will repeat on the next URL, and the
      -- secure channel is unusable anyway. Only an empty list is worth
      -- retrying with a different endpoint URL.
      break
    end
  end

  if not endpoints or #endpoints == 0 then
    out["Endpoints"] = "none returned" .. (err and (" (" .. err .. ")") or "")
    return nil
  end

  return endpoints
end

local function action_port(host, port)
  local out = stdnse.output_table()

  local conn = opcua.Connection:new(host, port,
    {timeout = tonumber(arg_timeout), endpoint_url = arg_url,
     recv_buffer = tonumber(arg_buffer)})

  local status, err = conn:connect()
  if not status then
    -- An ERR response still proves the peer speaks OPC UA.
    if conn.hello_error then
      port.version.name = "opcua-tcp"
      port.version.product = "OPC UA Server"
      nmap.set_port_version(host, port)
      out["Protocol"] = "OPC UA Binary (opc.tcp)"
      out["Status"] = "confirmed by protocol error response"
      out["Server response"] = err
      conn:close()
      return out
    end
    stdnse.debug1("connect failed: %s", tostring(err))
    conn:close()
    return nil
  end

  port.version.name = "opcua-tcp"
  port.version.product = "OPC UA Server"
  nmap.set_port_version(host, port)

  out["Protocol"] = "OPC UA Binary (opc.tcp)"
  if conn.ack then
    out["Transport"] = string.format(
      "protocol version %d, receive buffer %d, send buffer %d, max message %s, max chunks %s",
      conn.ack.protocol_version, conn.ack.recv_buffer, conn.ack.send_buffer,
      conn.ack.max_message_size == 0 and "unlimited" or tostring(conn.ack.max_message_size),
      conn.ack.max_chunk_count == 0 and "unlimited" or tostring(conn.ack.max_chunk_count))
  end

  status, err = conn:open_secure_channel()
  if not status then
    out["Status"] = "OPC UA confirmed, endpoint enumeration failed"
    out["Error"] = err
    conn:close()
    return out
  end

  local endpoints = enumerate(conn, host, port, out)
  if not endpoints then
    conn:close()
    return out
  end

  -- Application description from the first endpoint.
  local app = endpoints[1].server
  if app then
    local server = stdnse.output_table()
    if app.application_name and app.application_name ~= "" then
      server["Application Name"] = app.application_name
    end
    if app.application_uri and app.application_uri ~= "" then
      server["Application URI"] = app.application_uri
    end
    if app.product_uri and app.product_uri ~= "" then
      server["Product URI"] = app.product_uri
    end
    server["Application Type"] = app.application_type
    if app.gateway_server_uri and app.gateway_server_uri ~= "" then
      server["Gateway Server URI"] = app.gateway_server_uri
    end
    if app.discovery_urls and #app.discovery_urls > 0 then
      server["Discovery URLs"] = app.discovery_urls
    end
    out["Server"] = server

    if app.application_name and app.application_name ~= "" then
      port.version.extrainfo = app.application_name
      nmap.set_port_version(host, port)
    end
  end

  -- Endpoint list.
  local ep_out = stdnse.output_table()
  local certs_seen = {}
  for i, ep in ipairs(endpoints) do
    local e = stdnse.output_table()
    e["URL"] = ep.endpoint_url
    e["Security"] = string.format("%s / %s (level %s)",
      ep.security_mode, opcua.policy_name(ep.security_policy_uri),
      tostring(ep.security_level))
    e["User tokens"] = format_tokens(ep)
    if ep.transport_profile_uri and
       ep.transport_profile_uri ~= opcua.TRANSPORT_PROFILE_BINARY then
      e["Transport profile"] = ep.transport_profile_uri
    end
    ep_out[tostring(i)] = e

    if ep.server_certificate and #ep.server_certificate > 0 then
      local cert = ep.certificate or
        opcua.analyze_certificate(ep.server_certificate,
                                  ep.server and ep.server.application_uri)
      if cert then
        ep.certificate = cert
        local key = cert.fingerprint_sha256 or cert.subject
        if not certs_seen[key] then
          certs_seen[key] = cert
          record_certificate(host, port, cert)
        end
      end
    end
  end
  out[string.format("Endpoints (%d)", #endpoints)] = ep_out

  -- Certificates (usually one, shared by every endpoint).
  if enabled(arg_certs, true) then
    local n = 0
    for _, cert in pairs(certs_seen) do
      n = n + 1
      local label = n == 1 and "Server Certificate" or
                    string.format("Server Certificate %d", n)
      out[label] = certificate_output(cert)
    end
  end

  -- Findings.
  local findings = opcua.assess_endpoints(endpoints)
  if #findings > 0 then
    local list = {}
    for _, f in ipairs(findings) do
      local where = ""
      if #f.endpoints == 1 then
        where = string.format(" (endpoint %d)", f.endpoints[1])
      elseif #f.endpoints > 1 then
        where = string.format(" (endpoints %s)", table.concat(f.endpoints, ", "))
      end
      list[#list + 1] = string.format("%s: %s%s -- %s",
        f.severity:upper(), f.title, where, f.detail)
    end
    out["Security Findings"] = list

    if arg_vulns then
      local report = vulns_report(host, port, findings, endpoints)
      if report then
        out["Vulnerabilities"] = report
      end
    end
  end

  -- Lateral discovery.
  if enabled(arg_find, true) then
    local servers = conn:find_servers(conn.used_url)
    if servers and #servers > 0 then
      local known = {}
      local urls = {}
      for _, s in ipairs(servers) do
        local label = s.application_name or s.application_uri or "unnamed"
        local first_url = s.discovery_urls and s.discovery_urls[1]
        if first_url then
          label = string.format("%s (%s)", label, first_url)
        end
        known[#known + 1] = label
        for _, u in ipairs(s.discovery_urls or {}) do
          urls[#urls + 1] = u
        end
      end
      -- Only interesting if it tells us about more than this very server.
      if #servers > 1 or (servers[1] and servers[1].discovery_urls and
                          #servers[1].discovery_urls > 0) then
        out["Known Servers (FindServers)"] = known
      end
      add_targets(host, urls, out)
    end

    local network = conn:find_servers_on_network()
    if network and #network > 0 then
      local list = {}
      local urls = {}
      for _, s in ipairs(network) do
        local caps = (s.server_capabilities and #s.server_capabilities > 0) and
          (" [" .. table.concat(s.server_capabilities, ",") .. "]") or ""
        list[#list + 1] = string.format("%s -> %s%s",
          tostring(s.server_name), tostring(s.discovery_url), caps)
        urls[#urls + 1] = s.discovery_url
      end
      out["Local Discovery Server Registrations"] = list
      add_targets(host, urls, out)
    end
  end

  conn:close()
  return out
end

--- Reports certificates that appear on more than one host.
local function action_post()
  local shared = {}
  for fingerprint, entry in pairs(nmap.registry.opcua_certs or {}) do
    if #entry.hosts > 1 then
      shared[#shared + 1] = string.format("%s used by %d hosts: %s (%s)",
        fingerprint:sub(1, 16) .. "...", #entry.hosts,
        table.concat(entry.hosts, ", "), tostring(entry.subject))
    end
  end
  if #shared == 0 then return nil end
  table.sort(shared)
  local out = stdnse.output_table()
  out["Shared server certificates"] = shared
  return out
end

action = function(host, port)
  if SCRIPT_TYPE == "postrule" then
    return action_post()
  end
  return action_port(host, port)
end
