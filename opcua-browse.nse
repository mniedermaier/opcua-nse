local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local opcua = require "opcua"

description = [[
Browses the address space of an OPC UA server and reports which nodes the
session is allowed to change.

The script opens a session (anonymous unless credentials are given), walks the
Objects folder breadth first and reads the AccessLevel and UserAccessLevel
attributes of every variable it finds, plus Executable and UserExecutable for
methods. UserAccessLevel is what the current session may actually do, so a
variable reported as writable here is writable by whoever can reach the port.

On a plant this is the difference between an information leak and a control
problem: an anonymous session that may write a setpoint can change the process.
The script establishes that from the access level bits alone - it never writes
a value and never calls a method, so nothing on the target changes.
]]

---
-- @usage
-- nmap -p 4840 --script opcua-browse <target>
-- nmap -p 4840 --script opcua-browse --script-args opcua-browse.depth=4,opcua-browse.max-nodes=500 <target>
--
-- @output
-- PORT     STATE SERVICE
-- 4840/tcp open  opcua-tcp
-- | opcua-browse:
-- |   Session: anonymous (SecurityMode None)
-- |   Address space: 12 nodes visited, depth 3
-- |   Writable by this session (2):
-- |     ns=2;i=6 Plant/Temperature (Double) read+write
-- |     ns=2;i=7 Plant/Setpoint (Double) read+write
-- |   Methods callable by this session (1):
-- |     ns=2;i=9 Plant/Multiply
-- |   Nodes:
-- |     Objects
-- |       Server (Object)
-- |       Plant (Object)
-- |         Temperature (Variable) read+write
-- |         Pressure (Variable) read+write
-- |         SerialNumber (Variable) read
-- |_        Multiply (Method) executable
--
-- @args opcua-browse.depth How many levels below the Objects folder to walk.
--       Default: 3
-- @args opcua-browse.max-nodes Stop after this many nodes. Default: 200
-- @args opcua-browse.root NodeId to start from, as a plain numeric identifier
--       in namespace 0. Default: 85 (the Objects folder)
-- @args opcua-browse.tree Print the full node tree, not just the summary.
--       Default: true
-- @args opcua-browse.username User name for the session (anonymous otherwise).
-- @args opcua-browse.password Password for opcua-browse.username.
-- @args opcua-browse.timeout Socket timeout in milliseconds.

author = "Matthias Niedermaier"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

portrule = shortport.port_or_service(opcua.PORTS, opcua.SERVICES, "tcp")

local arg_depth = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".depth")) or 3
local arg_max = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".max-nodes")) or 200
local arg_root = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".root"))
local arg_tree = stdnse.get_script_args(SCRIPT_NAME .. ".tree")
local arg_username = stdnse.get_script_args(SCRIPT_NAME .. ".username")
local arg_password = stdnse.get_script_args(SCRIPT_NAME .. ".password")
local arg_timeout = stdnse.get_script_args(SCRIPT_NAME .. ".timeout")

--- Walks the address space breadth first.
-- @return table nodes in visit order, each {node, name, path, class, depth, children}
local function walk(conn, root, max_depth, max_nodes)
  local visited = {}
  local nodes = {}
  local queue = {{node = root, path = "", depth = 0}}
  local truncated = false
  local first_error = nil

  while #queue > 0 do
    local item = table.remove(queue, 1)
    if #nodes >= max_nodes then
      truncated = true
      break
    end

    local refs, err = conn:browse(item.node, {max_refs = 0})
    if not refs then
      first_error = first_error or err
      stdnse.debug1("browse of %s failed: %s",
        opcua.nodeid_string(item.node) or tostring(item.node), tostring(err))
    else
      for _, ref in ipairs(refs) do
        local key = opcua.nodeid_string(ref.node_id)
        -- Server-internal references may point back into visited subtrees.
        if key and not visited[key] and ref.node_id.server_index == nil then
          visited[key] = true
          local name = ref.browse_name and ref.browse_name.name or
                       ref.display_name or key
          local entry = {
            node = ref.node_id,
            id = key,
            name = name,
            path = item.path == "" and name or (item.path .. "/" .. name),
            class = ref.node_class,
            depth = item.depth + 1,
          }
          nodes[#nodes + 1] = entry
          if item.depth + 1 < max_depth and #nodes < max_nodes then
            queue[#queue + 1] = {node = ref.node_id, path = entry.path,
                                 depth = item.depth + 1}
          end
        end
      end
    end
  end

  return nodes, truncated, first_error
end

--- Reads the access-relevant attributes for the collected nodes, in batches.
local function read_access(conn, nodes)
  local requests = {}
  local map = {}

  for _, entry in ipairs(nodes) do
    if entry.class == "Variable" then
      requests[#requests + 1] = {node = entry.node, attr = opcua.ATTR.AccessLevel}
      map[#requests] = {entry = entry, field = "access_level"}
      requests[#requests + 1] = {node = entry.node, attr = opcua.ATTR.UserAccessLevel}
      map[#requests] = {entry = entry, field = "user_access_level"}
      requests[#requests + 1] = {node = entry.node, attr = opcua.ATTR.DataType}
      map[#requests] = {entry = entry, field = "data_type"}
    elseif entry.class == "Method" then
      requests[#requests + 1] = {node = entry.node, attr = opcua.ATTR.Executable}
      map[#requests] = {entry = entry, field = "executable"}
      requests[#requests + 1] = {node = entry.node, attr = opcua.ATTR.UserExecutable}
      map[#requests] = {entry = entry, field = "user_executable"}
    end
  end

  -- Servers cap the number of operations per request; 100 is a safe batch size.
  local batch_size = 100
  local index = 1
  while index <= #requests do
    local batch = {}
    for i = index, math.min(index + batch_size - 1, #requests) do
      batch[#batch + 1] = requests[i]
    end
    local values, err = conn:read(batch)
    if not values then
      stdnse.debug1("attribute read failed: %s", tostring(err))
      return
    end
    for i, dv in ipairs(values) do
      local target = map[index + i - 1]
      if target and dv.value ~= nil and
         (not dv.status or opcua.is_good(dv.status)) then
        target.entry[target.field] = dv.value
      end
    end
    index = index + batch_size
  end
end

action = function(host, port)
  local out = stdnse.output_table()

  local conn = opcua.Connection:new(host, port, {timeout = tonumber(arg_timeout)})
  local status, err = conn:connect()
  if not status then
    conn:close()
    return nil
  end
  status, err = conn:open_secure_channel()
  if not status then
    conn:close()
    return nil
  end

  local endpoints = conn:get_endpoints()
  if not endpoints or #endpoints == 0 then
    conn:close()
    return nil
  end

  local token_type = arg_username and "UserName" or "Anonymous"
  local endpoint, token = opcua.pick_session_endpoint(endpoints, token_type)
  if not endpoint then
    conn:close()
    return nil
  end

  status, err = conn:create_session({
    endpoint_url = endpoint.endpoint_url,
    username = arg_username,
    password = arg_password,
    policy_id = token and token.policy_id,
  })
  if not status then
    out["Session"] = "failed: " .. tostring(err)
    conn:close()
    return out
  end

  out["Session"] = string.format("%s (SecurityMode %s)",
    arg_username and ("user " .. arg_username) or "anonymous",
    endpoint.security_mode)

  local root = arg_root and {ns = 0, type = "numeric", id = arg_root}
               or opcua.NODE.Objects
  local nodes, truncated, browse_error = walk(conn, root, arg_depth, arg_max)

  if #nodes == 0 then
    out["Address space"] = browse_error and
      string.format("not readable: %s -- the session is not authorised to "
        .. "browse; access control is enforced", browse_error)
      or "empty"
    conn:close()
    return out
  end

  read_access(conn, nodes)

  out["Address space"] = string.format("%d nodes visited, depth %d%s",
    #nodes, arg_depth, truncated and " (stopped at max-nodes)" or "")

  local writable, callable = {}, {}
  for _, entry in ipairs(nodes) do
    if entry.class == "Variable" then
      -- UserAccessLevel is what this session may do; fall back to AccessLevel.
      local effective = entry.user_access_level or entry.access_level
      if effective and (effective & 0x02) ~= 0 then
        writable[#writable + 1] = string.format("%s %s %s",
          entry.id, entry.path, opcua.access_level_string(effective))
      end
    elseif entry.class == "Method" then
      local exec = entry.user_executable
      if exec == nil then exec = entry.executable end
      if exec then
        callable[#callable + 1] = string.format("%s %s", entry.id, entry.path)
      end
    end
  end

  if #writable > 0 then
    out[string.format("Writable by this session (%d)", #writable)] = writable
  end
  if #callable > 0 then
    out[string.format("Methods callable by this session (%d)", #callable)] = callable
  end

  if #writable > 0 and not arg_username then
    out["Finding"] = string.format(
      "HIGH: an anonymous session can write %d variable(s); anyone able to reach this port can change process data.",
      #writable)
  end

  if arg_tree == nil or not (arg_tree == "false" or arg_tree == "0") then
    -- Sort by path so children follow their parent instead of appearing in
    -- breadth-first visit order.
    local ordered = {}
    for _, entry in ipairs(nodes) do ordered[#ordered + 1] = entry end
    table.sort(ordered, function(a, b) return a.path < b.path end)

    local tree = {}
    for _, entry in ipairs(ordered) do
      local indent = string.rep("  ", entry.depth - 1)
      local suffix = ""
      if entry.class == "Variable" then
        local effective = entry.user_access_level or entry.access_level
        suffix = " " .. (opcua.access_level_string(effective) or "?")
      elseif entry.class == "Method" then
        local exec = entry.user_executable
        if exec == nil then exec = entry.executable end
        suffix = exec and " executable" or " not executable"
      end
      tree[#tree + 1] = string.format("%s%s (%s)%s", indent, entry.name,
        entry.class, suffix)
    end
    out["Nodes"] = tree
  end

  conn:close()
  return out
end
