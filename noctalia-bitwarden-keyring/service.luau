--!nonstrict

local PANEL_ID = "frap129/noctalia-bitwarden-keyring:unlock"

local active = nil
local pendingId = nil
local generation = 0
local fetching = false
local posting = false
local polling = false

local function validId(value)
  return type(value)=="string" and #value==32 and string.match(value,"^[0-9a-f]+$")~=nil
end

local function descriptorPath(id)
  local runtimeDir=noctalia.getenv("XDG_RUNTIME_DIR")
  if type(runtimeDir)~="string" or string.sub(runtimeDir,1,1)~="/" then return nil end
  return runtimeDir.."/bitwarden-keyring/noctalia-"..id..".json"
end

local function validDescriptor(value,id)
 return type(value)=="table" and value.version==1 and value.request_id==id
  and type(value.token)=="string" and #value.token==64 and string.match(value.token,"^[0-9a-f]+$")~=nil
  and type(value.base_url)=="string" and string.match(value.base_url,"^http://127%.0%.0%.1:%d+$")~=nil
end

local function translated(key)
  return noctalia.tr(key)
end

local function publish(id, title, prompt, confirmOnly, phase, errorText)
  noctalia.state.set("auth", {
    id = id,
    title = title,
    prompt = prompt,
    confirm_only = confirmOnly,
    phase = phase,
    error = errorText,
  })
end

local function openPanel()
  if noctalia.state.get("panel_open") ~= true then
    noctalia.togglePanel(PANEL_ID)
  end
end

local function finish(phase, errorText)
  local owner = active
  local id = pendingId or ""
  local title = ""
  local prompt = ""
  local confirmOnly = false
  if owner ~= nil then
    id = owner.id
    title = owner.title
    prompt = owner.prompt
    confirmOnly = owner.confirmOnly
  end
  generation = generation + 1
  if owner ~= nil then
    owner.token = nil
    owner.baseUrl = nil
    owner.request = nil
    owner.body = nil
    owner.password = nil
  end
  active = nil
  pendingId = nil
  fetching = false
  posting = false
  polling = false
  publish(id, title, prompt, confirmOnly, phase, errorText)
end

local function bridgeFailure()
  finish("failed", translated("panel.bridge_unreachable"))
end

local function requestHeaders(token)
  return {
    Authorization = "Bearer " .. token,
    Accept = "application/json",
    ["Cache-Control"] = "no-store",
  }
end

local function responseHeaders(token)
  local headers = requestHeaders(token)
  headers["Content-Type"] = "application/json"
  return headers
end

local function validRequest(value, id)
  return type(value) == "table" and value.type == "keyring_request" and value.cookie == id
    and type(value.title) == "string" and type(value.message) == "string"
    and type(value.confirm_only) == "boolean"
end

local function openRequest(id)
  if active ~= nil or fetching or pendingId ~= nil then return end
  pendingId = id
  generation = generation + 1
  local capturedGeneration = generation
  local capturedId = id
  fetching = true

  local path = descriptorPath(id)
  if path == nil then
    finish("failed", translated("panel.invalid_request"))
    return
  end
  local raw = noctalia.readFile(path)
  if type(raw) ~= "string" then
    finish("failed", translated("panel.invalid_request"))
    return
  end
  local decoded, descriptor = pcall(noctalia.json.decode, raw)
  raw = nil
  if not decoded or not validDescriptor(descriptor, id) then
    descriptor = nil
    finish("failed", translated("panel.invalid_request"))
    return
  end

  local baseUrl = descriptor.base_url
  local token = descriptor.token
  descriptor.token = nil
  descriptor.base_url = nil
  descriptor = nil
  local started = noctalia.http.request({
    method = "GET",
    url = baseUrl .. "/v1/request",
    headers = requestHeaders(token),
  }, function(res)
    if capturedGeneration ~= generation or capturedId ~= pendingId then return end
    fetching = false
    if type(res) ~= "table" or res.error ~= nil or res.status ~= 200 or type(res.body) ~= "string" then
      token = nil
      baseUrl = nil
      bridgeFailure()
      return
    end
    local decodedRequest, request = pcall(noctalia.json.decode, res.body)
    if not decodedRequest or not validRequest(request, capturedId) then
      token = nil
      baseUrl = nil
      finish("failed", translated("panel.invalid_request"))
      return
    end
    active = {
      id = capturedId,
      title = request.title,
      prompt = request.message,
      confirmOnly = request.confirm_only == true,
      phase = "ready",
      token = token,
      baseUrl = baseUrl,
      request = request,
    }
    request = nil
    token = nil
    baseUrl = nil
    pendingId = nil
    publish(active.id, active.title, active.prompt, active.confirmOnly, "ready", "")
    openPanel()
  end)
  if started == false then
    token = nil
    baseUrl = nil
    fetching = false
    bridgeFailure()
  end
end

local function validAction(action)
  return action == "submit" or action == "cancel" or action == "confirm"
end

local function onCommand(value)
  if type(value) ~= "table" then
    noctalia.state.set("command", nil)
    return
  end
  local id = value.id
  local action = value.action
  local password = value.password
  value.password = nil
  noctalia.state.set("command", nil)
  if not validId(id) or not validAction(action) then password = nil return end
  if active == nil or id ~= active.id or active.phase ~= "ready" or posting then password = nil return end
  if action == "submit" and (type(password) ~= "string" or #password == 0) then password = nil return end
  if action == "confirm" and active.confirmOnly ~= true then password = nil return end
  if action ~= "submit" then password = nil end

  local result = action == "submit" and "ok" or (action == "cancel" and "cancelled" or "confirmed")
  local wire = {type = "keyring_response", id = id, result = result}
  if action == "submit" then wire.password = password end
  local encoded, body = pcall(noctalia.json.encode, wire)
  wire.password = nil
  password = nil
  wire = nil
  if not encoded or type(body) ~= "string" then body = nil return end

  local capturedGeneration = generation
  local capturedId = id
  posting = true
  active.phase = action == "submit" and "busy" or "cancelling"
  if action == "submit" then
    publish(active.id, active.title, active.prompt, active.confirmOnly, "busy", "")
  end
  local started = noctalia.http.request({
    method = "POST",
    url = active.baseUrl .. "/v1/response",
    headers = responseHeaders(active.token),
    body = body,
  }, function(res)
    body = nil
    if capturedGeneration ~= generation or active == nil or capturedId ~= active.id then return end
    posting = false
    if type(res) ~= "table" or res.error ~= nil or res.status ~= 202 then bridgeFailure() return end
    if action == "cancel" then
      finish("cancelled", translated("panel.cancelled"))
    elseif action == "confirm" then
      finish("confirmed", translated("panel.success"))
    end
  end)
  if started == false then
    body = nil
    posting = false
    bridgeFailure()
  end
end

local function validResult(value, id)
  return type(value) == "table" and value.type == "keyring_result" and value.id == id
    and type(value.success) == "boolean" and type(value.retry) == "boolean"
end

function update()
  if active == nil or (active.phase ~= "ready" and active.phase ~= "busy") then return end
  if fetching or posting or polling then return end
  if not validId(active.id) then bridgeFailure() return end
  local capturedGeneration = generation
  local capturedId = active.id
  polling = true
  local started = noctalia.http.request({
    method = "GET",
    url = active.baseUrl .. "/v1/result?id=" .. capturedId,
    headers = requestHeaders(active.token),
  }, function(res)
    if capturedGeneration ~= generation or active == nil or capturedId ~= active.id then return end
    polling = false
    if type(res) ~= "table" or res.error ~= nil or type(res.status) ~= "number" then bridgeFailure() return end
    local status = res.status
    if status ~= 200 and status ~= 204 and status ~= 409 then bridgeFailure() return end
    if status == 204 or status == 409 then return end
    if type(res.body) ~= "string" then bridgeFailure() return end
    local decoded, result = pcall(noctalia.json.decode, res.body)
    if not decoded or not validResult(result, capturedId) then bridgeFailure() return end
    if result.success == true then
      finish("success", translated("panel.success"))
    elseif result.retry == true then
      active.phase = "ready"
      posting = false
      polling = false
      publish(active.id, active.title, active.prompt, active.confirmOnly, "ready", translated("panel.incorrect_password"))
      openPanel()
    else
      finish("failed", translated("panel.unlock_failed"))
    end
  end)
  if started == false then
    polling = false
    bridgeFailure()
  end
end

function onIpc(event, payload)
  if event ~= "keyring_request" or not validId(payload) then return end
  if active ~= nil or fetching or pendingId ~= nil then return end
  openRequest(payload)
end

function onExit()
  generation = generation + 1
  if active ~= nil then
    active.token = nil
    active.baseUrl = nil
    active.request = nil
    active.body = nil
    active.password = nil
  end
  active = nil
  pendingId = nil
  fetching = false
  posting = false
  polling = false
  noctalia.state.set("command", nil)
  noctalia.state.set("auth", false)
end

noctalia.state.set("command", nil)
noctalia.state.set("auth", false)
noctalia.state.watch("command", onCommand)
noctalia.setUpdateInterval(250)
