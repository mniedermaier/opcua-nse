local brute = require "brute"
local creds = require "creds"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local opcua = require "opcua"

description = [[
Performs password guessing against the UserName identity token of an OPC UA
server.

For every candidate the script creates a session and calls ActivateSession with
a UserNameIdentityToken, which is the same path a real client takes. Servers
that accept the credentials return Good; anything else comes back as
Bad_UserAccessDenied or Bad_IdentityTokenRejected, so valid accounts are
distinguishable without any side effect on the address space.

The script requires an endpoint whose UserName token policy is None, because
any other policy requires the password to be encrypted with the server's public
key. That restriction is itself the finding: if this script can run at all, the
server accepts passwords in cleartext.
]]

---
-- @usage
-- nmap -p 4840 --script opcua-brute <target>
-- nmap -p 4840 --script opcua-brute --script-args userdb=users.txt,passdb=pass.txt <target>
--
-- @output
-- PORT     STATE SERVICE
-- 4840/tcp open  opcua-tcp
-- | opcua-brute:
-- |   Accounts:
-- |     operator:operator - Valid credentials
-- |   Note: this endpoint accepts UserName tokens over SecurityPolicy None,
-- |_  so passwords are transmitted in cleartext.
--
-- @args opcua-brute.endpoint-url Endpoint URL to authenticate against.
-- @args opcua-brute.timeout Socket timeout in milliseconds.

author = "Matthias Niedermaier"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"brute", "intrusive"}

portrule = shortport.port_or_service(opcua.PORTS, opcua.SERVICES, "tcp")

local arg_url = stdnse.get_script_args(SCRIPT_NAME .. ".endpoint-url")
local arg_timeout = stdnse.get_script_args(SCRIPT_NAME .. ".timeout")

Driver = {}
Driver.__index = Driver

function Driver:new(host, port, options)
  return setmetatable({host = host, port = port, options = options or {}}, Driver)
end

-- Status codes a server returns for credentials it does not accept. Anything
-- else is treated as a transport problem worth retrying.
local REJECTED = {
  "Bad_UserAccessDenied", "Bad_IdentityTokenRejected", "Bad_IdentityTokenInvalid",
  "Bad_SecurityChecksFailed", "Bad_UserSignatureInvalid",
}

--- Establishes the transport and remembers which endpoint accepts UserName
-- tokens. Each guess then runs on its own connection, because a server may
-- drop the channel after a failed ActivateSession.
function Driver:connect()
  local conn = opcua.Connection:new(self.host, self.port,
    {timeout = tonumber(arg_timeout), endpoint_url = arg_url})

  local status, err = conn:connect()
  if not status then
    return false, brute.Error:new("connect failed: " .. tostring(err))
  end
  status, err = conn:open_secure_channel()
  if not status then
    conn:close()
    return false, brute.Error:new("secure channel failed: " .. tostring(err))
  end

  local endpoints = conn:get_endpoints(arg_url)
  if not endpoints or #endpoints == 0 then
    conn:close()
    return false, brute.Error:new("no endpoints")
  end

  local endpoint, token = opcua.pick_session_endpoint(endpoints, "UserName")
  conn:close()

  if not endpoint or not token then
    local abort = brute.Error:new(
      "no endpoint accepts UserName tokens over an unencrypted channel")
    abort:setAbort(true)
    return false, abort
  end

  self.endpoint_url = arg_url or endpoint.endpoint_url
  self.policy_id = token.policy_id
  return true
end

--- Tries one credential pair on a connection of its own.
function Driver:login(username, password)
  local conn = opcua.Connection:new(self.host, self.port,
    {timeout = tonumber(arg_timeout), endpoint_url = self.endpoint_url})

  local status, err = conn:connect()
  if status then
    status, err = conn:open_secure_channel()
  end
  if not status then
    conn:close()
    local retry = brute.Error:new("transport failed: " .. tostring(err))
    retry:setRetry(true)
    return false, retry
  end

  status, err = conn:create_session({
    endpoint_url = self.endpoint_url,
    username = username,
    password = password,
    policy_id = self.policy_id,
    session_name = "nmap-opcua-brute",
  })
  conn:close()

  if status then
    return true, creds.Account:new(username, password, creds.State.VALID)
  end

  local message = tostring(err)
  for _, code in ipairs(REJECTED) do
    if message:find(code, 1, true) then
      return false, brute.Error:new("invalid credentials")
    end
  end

  stdnse.debug1("login for %s failed unexpectedly: %s", username, message)
  local retry = brute.Error:new(message)
  retry:setRetry(true)
  return false, retry
end

function Driver:disconnect()
  return true
end

action = function(host, port)
  local engine = brute.Engine:new(Driver, host, port)
  engine.options.script_name = SCRIPT_NAME
  engine.options:setTitle("Accounts")

  local status, result = engine:start()
  if not status then
    return result
  end

  -- Reaching this point means UserName tokens were accepted unencrypted.
  if type(result) == "table" then
    result["Note"] = "this endpoint accepts UserName tokens over SecurityPolicy None, so passwords are transmitted in cleartext"
  end
  return result
end
