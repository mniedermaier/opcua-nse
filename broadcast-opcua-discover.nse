local dnssd = require "dnssd"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"
local opcua = require "opcua"

description = [[
Finds OPC UA servers on the local network segment without scanning a single
port, by asking for them over multicast DNS.

OPC 10000-12 has every host with OPC UA applications run a Local Discovery
Server with the multicast extension, which announces its servers as
<code>_opcua-tcp._tcp.local</code>. Servers that do this answer a single
multicast query with their discovery URL, so one packet can map a plant segment
that a port scan would take minutes to cover - including servers on ports
nobody would think to scan.

With <code>--script-args newtargets</code> the hosts found are added to the scan
queue, so opcua-discover can pick them up in the same run.
]]

---
-- @usage
-- nmap --script broadcast-opcua-discover
-- nmap --script broadcast-opcua-discover --script-args newtargets -p 4840 -sn
--
-- @output
-- Pre-scan script results:
-- | broadcast-opcua-discover:
-- |   192.0.2.10:
-- |     Name: SimulationServer
-- |     Discovery URL: opc.tcp://192.0.2.10:4840/UA/SimulationServer
-- |     Capabilities: LDS,DA
-- |   192.0.2.11:
-- |     Name: PlantGateway
-- |_    Discovery URL: opc.tcp://192.0.2.11:48010
--
-- @args newtargets Add the hosts found to the scan queue.

author = "Matthias Niedermaier"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"broadcast", "discovery", "safe"}

prerule = function() return true end

local SERVICE = "_opcua-tcp._tcp.local"

--- Turns one service record from the dnssd helper into a flat table.
-- The helper hands back a service named "<port>/<proto> <service>" followed by
-- the TXT properties and an "Address=" line. On a multicast query the peer name
-- is the multicast group, so the address has to come from that line.
local function parse_service(service)
  local info = {properties = {}}
  if type(service) ~= "table" then return info end

  if type(service.name) == "string" then
    info.port = tonumber(service.name:match("^(%d+)/"))
  end

  for _, line in ipairs(service) do
    local key, value = tostring(line):match("^([^=]+)=(.*)$")
    if key == "Address" then
      info.address = value
    elseif key then
      info.properties[key:lower()] = value
    end
  end

  return info
end

action = function()
  local helper = dnssd.Helper:new()
  helper:setMulticast(true)

  local status, result = helper:queryServices(SERVICE)
  if not status then
    stdnse.debug1("multicast query failed: %s", tostring(result))
    return nil
  end
  if type(result) ~= "table" or #result == 0 then
    return nil
  end

  local out = stdnse.output_table()
  local found = 0

  for _, peer in ipairs(result) do
    for _, service in ipairs(peer) do
      local info = parse_service(service)
      -- Prefer the announced address; fall back to the peer, unless that is
      -- the multicast group we asked into.
      local address = info.address
      if not address and type(peer.name) == "string" and
         not peer.name:find("^2[23][%d]*%.") then
        address = peer.name
      end
      if address then
        local entry = stdnse.output_table()
        local path = info.properties.path or ""
        if info.port then
          entry["Discovery URL"] = string.format("opc.tcp://%s:%d%s",
            address, info.port, path)
        end
        if info.properties.caps then
          entry["Capabilities"] = info.properties.caps
        end
        for key, value in pairs(info.properties) do
          if key ~= "caps" and key ~= "path" then
            entry[key] = value
          end
        end

        if target.ALLOW_NEW_TARGETS then
          local added = target.add(address)
          if added then
            entry["Added to scan queue"] = address
          end
        end

        out[address] = entry
        found = found + 1
      end
    end
  end

  if found == 0 then return nil end
  return out
end
