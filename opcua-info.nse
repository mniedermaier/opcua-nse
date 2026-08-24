local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local opcua = require "opcua"

description = [[
Opens an OPC UA session and reads the server's own diagnostic nodes.

Where opcua-discover stops at the discovery services, this script creates and
activates a session - anonymously by default - and reads the standard Server
object:

* <code>BuildInfo</code>: manufacturer, product name and URI, software version,
  build number and build date. This is the only way to fingerprint the stack
  version over the network, and it is what Nmap's version detection is fed with.
* <code>ServerStatus</code>: state, start time and the server's own clock, which
  also reveals the clock skew against the scanning host.
* <code>NamespaceArray</code>: the namespace URIs identify vendor and device model.
* <code>ServiceLevel</code> and <code>Auditing</code>: a server with auditing
  disabled keeps no record of the very connections an assessment produces.
* The <code>RoleSet</code> node: its absence means the server predates the
  role based access control introduced in OPC UA 1.04.

Creating a session is a normal client operation but it is logged and counted by
the server, which is why this script is not in the safe category. Nothing is
written; every operation is a read.
]]

---
-- @usage
-- nmap -p 4840 --script opcua-info <target>
-- nmap -p 4840 --script opcua-info --script-args opcua-info.username=operator,opcua-info.password=operator <target>
--
-- @output
-- PORT     STATE SERVICE
-- 4840/tcp open  opcua-tcp
-- | opcua-info:
-- |   Session: anonymous on opc.tcp://192.0.2.10:4840/nse/ (SecurityMode None)
-- |   Build Information:
-- |     Manufacturer: FreeOpcUa
-- |     Product: FreeOpcUa Python Server
-- |     Product URI: urn:freeopcua.github.io:python:server
-- |     Software Version: 1.1.5
-- |     Build Number: 1
-- |     Build Date: 2024-03-01 00:00:00Z
-- |   Server Status:
-- |     State: Running
-- |     Started: 2026-08-24 12:31:30Z
-- |     Server time: 2026-08-24 12:45:02Z (clock skew 0s)
-- |   Namespaces:
-- |     0: http://opcfoundation.org/UA/
-- |     1: urn:opcua-nse:test:insecure
-- |     2: http://opcua-nse.test/plant
-- |   Auditing: disabled
-- |_  Role based access control: not supported (no RoleSet node)
--
-- @xmloutput
-- <table key="build_info">
--   <elem key="manufacturer">FreeOpcUa</elem>
--   <elem key="product">FreeOpcUa Python Server</elem>
--   <elem key="software_version">1.1.5</elem>
-- </table>
--
-- @args opcua-info.username User name for the session. Without it the script
--       requests an anonymous session.
-- @args opcua-info.password Password that goes with opcua-info.username.
--       Note that on a SecurityPolicy None endpoint it travels in cleartext.
-- @args opcua-info.timeout Socket timeout in milliseconds.
-- @args opcua-info.endpoint-url Endpoint URL to use instead of the discovered one.

author = "Matthias Niedermaier"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

portrule = shortport.port_or_service(opcua.PORTS, opcua.SERVICES, "tcp")

local arg_username = stdnse.get_script_args(SCRIPT_NAME .. ".username")
local arg_password = stdnse.get_script_args(SCRIPT_NAME .. ".password")
local arg_timeout = stdnse.get_script_args(SCRIPT_NAME .. ".timeout")
local arg_url = stdnse.get_script_args(SCRIPT_NAME .. ".endpoint-url")

-- Remembers why reads failed, so a session without read permission is
-- reported rather than silently producing an empty result.
local read_failure = nil

--- Reads one attribute and returns the plain value.
local function read_value(conn, node, attr)
  local values, err = conn:read({{node = node, attr = attr or opcua.ATTR.Value}})
  if not values or not values[1] then
    stdnse.debug1("read of node %s failed: %s", tostring(node), tostring(err))
    read_failure = read_failure or err
    return nil
  end
  local dv = values[1]
  if dv.status and not opcua.is_good(dv.status) then
    return nil, dv.status
  end
  return dv.value
end

--- Feeds the discovered build information into Nmap's version detection.
local function set_version(host, port, build, app_name)
  local product = build and build.product_name
  if product and product ~= "" then
    port.version.product = product
  else
    port.version.product = "OPC UA Server"
  end
  port.version.name = "opcua-tcp"
  if build and build.software_version and build.software_version ~= "" then
    port.version.version = build.software_version
    if build.build_number and build.build_number ~= "" then
      port.version.version = build.software_version .. " build " .. build.build_number
    end
  end
  local extra = {}
  if build and build.manufacturer_name and build.manufacturer_name ~= "" then
    extra[#extra + 1] = build.manufacturer_name
  end
  if app_name and app_name ~= "" then
    extra[#extra + 1] = app_name
  end
  if #extra > 0 then
    port.version.extrainfo = table.concat(extra, "; ")
  end

  -- Derive a CPE from the product URI where the vendor follows the convention
  -- urn:<vendor>:<product>.
  if build and build.product_uri then
    local vendor, product_part = build.product_uri:match("^urn:([^:]+):(.+)$")
    if vendor and product_part then
      vendor = vendor:gsub("[^%w%-_.]", "_"):lower()
      product_part = product_part:gsub("[^%w%-_.]", "_"):lower()
      local version = (build.software_version and build.software_version ~= "")
        and build.software_version or "-"
      port.version.cpe = port.version.cpe or {}
      port.version.cpe[#port.version.cpe + 1] =
        string.format("cpe:/a:%s:%s:%s", vendor, product_part, version)
    end
  end
  nmap.set_port_version(host, port)
end

action = function(host, port)
  local out = stdnse.output_table()

  local conn = opcua.Connection:new(host, port,
    {timeout = tonumber(arg_timeout), endpoint_url = arg_url})

  local status, err = conn:connect()
  if not status then
    stdnse.debug1("connect failed: %s", tostring(err))
    conn:close()
    return nil
  end

  status, err = conn:open_secure_channel()
  if not status then
    conn:close()
    return nil
  end

  local endpoints = conn:get_endpoints(arg_url)
  if not endpoints or #endpoints == 0 then
    conn:close()
    return nil
  end

  local token_type = arg_username and "UserName" or "Anonymous"
  local endpoint, token = opcua.pick_session_endpoint(endpoints, token_type)
  if not endpoint then
    out["Session"] = string.format(
      "not possible: no SecurityMode None endpoint accepting %s tokens", token_type)
    conn:close()
    return out
  end

  local session_url = arg_url or endpoint.endpoint_url
  status, err = conn:create_session({
    endpoint_url = session_url,
    username = arg_username,
    password = arg_password,
    policy_id = token and token.policy_id,
  })
  if not status then
    out["Session"] = "failed: " .. tostring(err)
    conn:close()
    return out
  end

  out["Session"] = string.format("%s on %s (SecurityMode %s)",
    arg_username and ("user " .. arg_username) or "anonymous",
    session_url, endpoint.security_mode)

  -- ServerStatus carries the build information as a structure.
  read_failure = nil
  local status_value = read_value(conn, opcua.NODE.ServerStatus)
  local server_status = opcua.decode_server_status(status_value)

  local build = server_status and server_status.build_info
  if not build then
    -- Fall back to the individual BuildInfo component nodes.
    build = {
      product_uri = read_value(conn, opcua.NODE.BuildInfo_ProductUri),
      manufacturer_name = read_value(conn, opcua.NODE.BuildInfo_ManufacturerName),
      product_name = read_value(conn, opcua.NODE.BuildInfo_ProductName),
      software_version = read_value(conn, opcua.NODE.BuildInfo_SoftwareVersion),
      build_number = read_value(conn, opcua.NODE.BuildInfo_BuildNumber),
      build_date = read_value(conn, opcua.NODE.BuildInfo_BuildDate),
    }
  end

  if build and (build.product_name or build.manufacturer_name) then
    local b = stdnse.output_table()
    if build.manufacturer_name then b["Manufacturer"] = build.manufacturer_name end
    if build.product_name then b["Product"] = build.product_name end
    if build.product_uri then b["Product URI"] = build.product_uri end
    if build.software_version then b["Software Version"] = build.software_version end
    if build.build_number then b["Build Number"] = build.build_number end
    if build.build_date then b["Build Date"] = opcua.time_string(build.build_date) end
    out["Build Information"] = b
  end

  if server_status then
    local st = stdnse.output_table()
    st["State"] = server_status.state
    if server_status.start_time then
      st["Started"] = opcua.time_string(server_status.start_time)
    end
    -- Some stacks only refresh CurrentTime on the individual node, not on the
    -- ServerStatus structure, so read it separately and prefer that value.
    local now_before = os.time()
    local current = read_value(conn, opcua.NODE.ServerStatus_CurrentTime)
                    or server_status.current_time
    if current then
      local skew = current - now_before
      st["Server time"] = string.format("%s (clock skew %+ds)",
        opcua.time_string(current), skew)
    end
    out["Server Status"] = st
  end

  local namespaces = read_value(conn, opcua.NODE.NamespaceArray)
  if type(namespaces) == "table" then
    local list = {}
    for i, uri in ipairs(namespaces) do
      list[#list + 1] = string.format("%d: %s", i - 1, tostring(uri))
    end
    out["Namespaces"] = list
  end

  local service_level = read_value(conn, opcua.NODE.ServiceLevel)
  if service_level then
    out["Service Level"] = string.format("%s/255", tostring(service_level))
  end

  -- The server's own counters: how many sessions are open, how many it has
  -- seen, and how many it has turned away.
  local diagnostics = opcua.decode_server_diagnostics(
    read_value(conn, opcua.NODE.ServerDiagnosticsSummary))
  if diagnostics then
    local d = stdnse.output_table()
    d["Sessions"] = string.format("%d open, %d since start",
      diagnostics.current_session_count, diagnostics.cumulated_session_count)
    if diagnostics.rejected_session_count > 0 or
       diagnostics.security_rejected_session_count > 0 then
      d["Rejected sessions"] = string.format("%d rejected, %d on security grounds",
        diagnostics.rejected_session_count,
        diagnostics.security_rejected_session_count)
    end
    if diagnostics.security_rejected_requests_count > 0 then
      d["Rejected requests"] = string.format("%d on security grounds",
        diagnostics.security_rejected_requests_count)
    end
    if diagnostics.current_subscription_count > 0 then
      d["Subscriptions"] = string.format("%d active",
        diagnostics.current_subscription_count)
    end
    out["Diagnostics"] = d
  else
    local enabled = read_value(conn, opcua.NODE.DiagnosticsEnabledFlag)
    if enabled == false then
      out["Diagnostics"] = "disabled on this server"
    end
  end

  local auditing = read_value(conn, opcua.NODE.Auditing)
  if auditing ~= nil then
    out["Auditing"] = auditing and "enabled" or
      "disabled -- the server keeps no audit trail of client activity"
  end

  -- RoleSet exists only on servers implementing the 1.04 role model.
  local roles, role_status = read_value(conn, opcua.NODE.RoleSet,
                                        opcua.ATTR.NodeId)
  if roles then
    local refs = conn:browse(opcua.NODE.RoleSet)
    if refs and #refs > 0 then
      local names = {}
      for _, ref in ipairs(refs) do
        names[#names + 1] = ref.browse_name and ref.browse_name.name or "?"
      end
      out["Role based access control"] = string.format("%d roles: %s",
        #refs, table.concat(names, ", "))
    else
      out["Role based access control"] = "RoleSet present but empty"
    end
  else
    out["Role based access control"] = "not supported (no RoleSet node)" ..
      (role_status and string.format(" [%s]", opcua.status_string(role_status)) or "")
  end

  if read_failure and not out["Build Information"] and not out["Server Status"] then
    -- The session exists but may not read the Server object. That is the
    -- server enforcing access control, and worth reporting as such.
    out["Reads denied"] = string.format("%s -- the session is not authorised "
      .. "to read the Server object; access control is enforced", read_failure)
  end

  set_version(host, port, build, endpoint.server and endpoint.server.application_name)

  conn:close()
  return out
end
