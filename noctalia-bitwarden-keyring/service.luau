--!nonstrict

local PANEL_ID = "frap129/noctalia-bitwarden-keyring:unlock"

local active = nil
local pendingId = nil
local generation = 0
local fetching = false
local posting = false
local polling = false
local bridgeToken = nil
local bridgeBaseUrl = nil
local encodedBody = nil
local postAction = nil
local processingCommand = false
local commandIdentity = 0
local watcherRegistered = false
local startupRecovering = true
local lifecycle = {version = 1, active_id = "", phase = "", queue = {}}

local function validId(value)
  return type(value) == "string" and #value == 32 and string.match(value, "^[0-9a-f]+$") ~= nil
end

local function descriptorPath(id)
  local runtimeDir = noctalia.getenv("XDG_RUNTIME_DIR")
  if type(runtimeDir) ~= "string" or string.sub(runtimeDir, 1, 1) ~= "/" then return nil end
  return runtimeDir .. "/bitwarden-keyring/noctalia-" .. id .. ".json"
end

local function validDescriptor(value, id)
  return type(value) == "table" and value.version == 1 and value.request_id == id
    and type(value.token) == "string" and #value.token == 64 and string.match(value.token, "^[0-9a-f]+$") ~= nil
    and type(value.base_url) == "string" and string.match(value.base_url, "^http://127%.0%.0%.1:%d+$") ~= nil
end

local function loadDescriptor(id)
  local path = descriptorPath(id)
  if path == nil then return nil end
  local raw = noctalia.readFile(path)
  if type(raw) ~= "string" then return nil end
  local decoded, descriptor = pcall(noctalia.json.decode, raw)
  raw = nil
  if not decoded or not validDescriptor(descriptor, id) then return nil end
  return descriptor
end

local function persistLifecycle()
  local queue = {}
  for index, id in ipairs(lifecycle.queue) do
    queue[index] = id
  end
  local snapshot = {version = 1, active_id = lifecycle.active_id, phase = lifecycle.phase, queue = queue}
  noctalia.state.set("service_lifecycle", snapshot)
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

local function requestPanelOpen()
  if noctalia.state.get("panel_open") ~= true then
    noctalia.togglePanel(PANEL_ID)
  end
end

local function requestHeaders(token)
  return {
    "Authorization: Bearer " .. token,
    "Accept: application/json",
    "Cache-Control: no-store",
  }
end

local function responseHeaders(token)
  local headers = requestHeaders(token)
  table.insert(headers, "Content-Type: application/json")
  return headers
end

local function validRequest(value, id)
  return type(value) == "table" and value.type == "keyring_request" and value.cookie == id
    and type(value.title) == "string" and type(value.message) == "string"
    and type(value.confirm_only) == "boolean"
end

local function validResult(value, id)
  return type(value) == "table" and value.type == "keyring_result" and value.id == id
    and type(value.success) == "boolean"
    and (value.retry == nil or type(value.retry) == "boolean")
    and (value.error == nil or type(value.error) == "string")
end

local function clearCommand(value)
  processingCommand = true
  if type(value) == "table" then
    value.password = nil
  end
  noctalia.state.set("command", nil)
  value = nil
  processingCommand = false
end

local function clearAcknowledgedCommand(id, action, identity)
  local current = noctalia.state.get("command")
  if identity ~= commandIdentity or type(current) ~= "table" or current.id ~= id or current.action ~= action then return end
  clearCommand(current)
  current = nil
end

local function clearMatchingCommand(id)
  local current = noctalia.state.get("command")
  if type(current) == "table" and current.id == id then
    clearCommand(current)
  end
  current = nil
end

local function clearMatchingAuth(id)
  local current = noctalia.state.get("auth")
  if type(current) == "table" and current.id == id then
    noctalia.state.set("auth", false)
  end
  current = nil
end

local function invalidatePrivate()
  generation = generation + 1
  active = nil
  pendingId = nil
  fetching = false
  posting = false
  polling = false
  bridgeToken = nil
  bridgeBaseUrl = nil
  encodedBody = nil
  postAction = nil
end

local startNextRequest
local onCommand

local function dropOwnership()
  local oldId = lifecycle.active_id
  invalidatePrivate()
  lifecycle.active_id = ""
  lifecycle.phase = ""
  persistLifecycle()
  clearMatchingCommand(oldId)
  noctalia.state.set("auth", false)
  startNextRequest()
end

local function terminalFinish(phase, errorText)
  local owner = active
  local id = lifecycle.active_id
  local title = ""
  local prompt = ""
  local confirmOnly = false
  if owner ~= nil then
    title = owner.title
    prompt = owner.prompt
    confirmOnly = owner.confirmOnly
  end
  local showPanel = owner == nil and validId(pendingId)
  local terminal = {id = id, title = title, prompt = prompt, confirm_only = confirmOnly, phase = phase, error = errorText}
  noctalia.state.set("auth", terminal)
  invalidatePrivate()
  lifecycle.active_id = ""
  lifecycle.phase = ""
  persistLifecycle()
  if showPanel then
    requestPanelOpen()
  end
  startNextRequest()
end

local function bridgeFailure()
  terminalFinish("failed", translated("panel.bridge_unreachable"))
end

local function enqueueRequest(id)
  if not validId(id) or id == lifecycle.active_id then return end
  local descriptor = loadDescriptor(id)
  if descriptor == nil then return end
  descriptor.token = nil
  descriptor.base_url = nil
  descriptor = nil
  for _, queuedId in ipairs(lifecycle.queue) do
    if queuedId == id then return end
  end
  table.insert(lifecycle.queue, id)
  persistLifecycle()
end

local function registerCommandWatcher()
  if watcherRegistered then return end
  watcherRegistered = true
  noctalia.state.watch("command", onCommand)
end

local function finalizeStartupRecovery()
  if not startupRecovering then return end
  startupRecovering = false
  registerCommandWatcher()
end

local function openRequest(id, restoredPhase)
  pendingId = id
  generation = generation + 1
  local capturedGeneration = generation
  local capturedId = id
  fetching = true

  local descriptor = loadDescriptor(id)
  if descriptor == nil then
    dropOwnership()
    return
  end
  bridgeBaseUrl = descriptor.base_url
  bridgeToken = descriptor.token
  descriptor.token = nil
  descriptor.base_url = nil
  descriptor = nil

  local started = noctalia.http({
    method = "GET",
    url = bridgeBaseUrl .. "/v1/request",
    headers = requestHeaders(bridgeToken),
  }, function(res)
    if capturedGeneration ~= generation or capturedId ~= pendingId then return end
    fetching = false
    if type(res) ~= "table" or res.error ~= nil or res.status ~= 200 or type(res.body) ~= "string" then
      bridgeFailure()
      return
    end
    local decodedRequest, request = pcall(noctalia.json.decode, res.body)
    if not decodedRequest or not validRequest(request, capturedId) then
      terminalFinish("failed", translated("panel.invalid_request"))
      return
    end
    local phase = restoredPhase == "busy" and "busy" or "ready"
    active = {id = capturedId, title = request.title, prompt = request.message, confirmOnly = request.confirm_only == true, phase = phase}
    request = nil
    pendingId = nil
    if lifecycle.phase ~= phase then
      lifecycle.phase = phase
      persistLifecycle()
    end
    local recoveryGeneration = generation
    local recoveryId = capturedId
    local retainedCommand = noctalia.state.get("command")
    if phase == "busy" then
      clearMatchingCommand(capturedId)
      publish(active.id, active.title, active.prompt, active.confirmOnly, "busy", "")
    elseif type(retainedCommand) == "table" and retainedCommand.id == capturedId then
      onCommand(retainedCommand)
      if recoveryGeneration == generation and active ~= nil and recoveryId == active.id and not posting then
        publish(active.id, active.title, active.prompt, active.confirmOnly, "ready", "")
        requestPanelOpen()
      end
    else
      publish(active.id, active.title, active.prompt, active.confirmOnly, "ready", "")
      requestPanelOpen()
    end
    retainedCommand = nil
    if recoveryGeneration == generation and active ~= nil and recoveryId == active.id then
      finalizeStartupRecovery()
    end
  end)
  if started == false then
    fetching = false
    bridgeFailure()
  end
end

startNextRequest = function()
  if lifecycle.active_id ~= "" or active ~= nil or fetching then return end
  local changed = false
  while #lifecycle.queue > 0 do
    local id = table.remove(lifecycle.queue, 1)
    changed = true
    local descriptor = loadDescriptor(id)
    if descriptor ~= nil then
      descriptor.token = nil
      descriptor.base_url = nil
      descriptor = nil
      lifecycle.active_id = id
      lifecycle.phase = "fetching"
      persistLifecycle()
      openRequest(id, "fetching")
      return
    end
  end
  if changed then
    persistLifecycle()
  end
  finalizeStartupRecovery()
end

local function validAction(action)
  return action == "submit" or action == "cancel" or action == "confirm"
end

onCommand = function(value)
  if type(value) ~= "table" then return end
  if processingCommand then return end
  commandIdentity = commandIdentity + 1
  local capturedCommandIdentity = commandIdentity
  if postAction ~= nil then return end
  local id = value.id
  local action = value.action
  local password = value.password
  if not validId(id) or not validAction(action) or active == nil or id ~= active.id or active.phase ~= "ready" or posting or postAction ~= nil
    or (action == "submit" and active.confirmOnly == true)
    or (action == "submit" and (type(password) ~= "string" or #password == 0))
    or (action == "confirm" and active.confirmOnly ~= true) then
    password = nil
    clearCommand(value)
    value = nil
    return
  end
  if action ~= "submit" then
    password = nil
  end
  local descriptor = loadDescriptor(id)
  if descriptor == nil then
    password = nil
    clearCommand(value)
    value = nil
    dropOwnership()
    return
  end
  bridgeBaseUrl = descriptor.base_url
  bridgeToken = descriptor.token
  descriptor.token = nil
  descriptor.base_url = nil
  descriptor = nil

  local result = action == "submit" and "ok" or (action == "cancel" and "cancelled" or "confirmed")
  local wire = {type = "keyring_response", id = id, result = result}
  if action == "submit" then
    wire.password = password
  end
  local encoded, body = pcall(noctalia.json.encode, wire)
  wire.password = nil
  password = nil
  wire = nil
  value = nil
  if not encoded or type(body) ~= "string" then
    body = nil
    return
  end

  local capturedGeneration = generation
  local capturedId = id
  local capturedAction = action
  encodedBody = body
  body = nil
  postAction = action
  action = nil
  posting = true
  publish(active.id, active.title, active.prompt, active.confirmOnly, "busy", "")
  local started = noctalia.http({
    method = "POST",
    url = bridgeBaseUrl .. "/v1/response",
    headers = responseHeaders(bridgeToken),
    body = encodedBody,
  }, function(res)
    if capturedGeneration ~= generation or active == nil or capturedId ~= active.id then return end
    encodedBody = nil
    posting = false
    if type(res) ~= "table" or res.error ~= nil or type(res.status) ~= "number" then
      postAction = nil
      return
    end
    local status = res.status
    if status ~= 202 and status ~= 409 and status ~= 410 then
      postAction = nil
      return
    end
    if status == 410 then
      clearAcknowledgedCommand(capturedId, capturedAction, capturedCommandIdentity)
      dropOwnership()
      return
    end
    active.phase = "busy"
    lifecycle.phase = "busy"
    persistLifecycle()
    clearAcknowledgedCommand(capturedId, capturedAction, capturedCommandIdentity)
    postAction = nil
    if capturedAction == "cancel" then
      terminalFinish("cancelled", translated("panel.cancelled"))
    elseif capturedAction == "confirm" then
      terminalFinish("confirmed", translated("panel.success"))
    end
  end)
  if started == false then
    encodedBody = nil
    posting = false
    postAction = nil
  end
end

local function activeDescriptorExists()
  local id = lifecycle.active_id
  if id == "" then return true end
  local descriptor = loadDescriptor(id)
  if descriptor == nil then return false end
  descriptor.token = nil
  descriptor.base_url = nil
  descriptor = nil
  return true
end

function update()
  if not activeDescriptorExists() then
    clearMatchingCommand(lifecycle.active_id)
    dropOwnership()
    return
  end
  if active == nil or (active.phase ~= "ready" and active.phase ~= "busy") then
    startNextRequest()
    return
  end
  if fetching or posting or polling then return end
  if not validId(active.id) then
    bridgeFailure()
    return
  end
  if active.phase == "ready" then
    local retainedCommand = noctalia.state.get("command")
    if retainedCommand ~= nil then
      onCommand(retainedCommand)
    end
    retainedCommand = nil
    if noctalia.state.get("panel_open") ~= true then
      requestPanelOpen()
    end
    return
  end
  clearMatchingCommand(active.id)
  local capturedGeneration = generation
  local capturedId = active.id
  polling = true
  local started = noctalia.http({
    method = "GET",
    url = bridgeBaseUrl .. "/v1/result?id=" .. capturedId,
    headers = requestHeaders(bridgeToken),
  }, function(res)
    if capturedGeneration ~= generation or active == nil or capturedId ~= active.id then return end
    polling = false
    if type(res) ~= "table" or res.error ~= nil or type(res.status) ~= "number" then
      bridgeFailure()
      return
    end
    local status = res.status
    if status ~= 200 and status ~= 204 and status ~= 409 then
      bridgeFailure()
      return
    end
    if status == 204 or status == 409 then return end
    if type(res.body) ~= "string" then
      bridgeFailure()
      return
    end
    local decoded, result = pcall(noctalia.json.decode, res.body)
    if not decoded or not validResult(result, capturedId) then
      bridgeFailure()
      return
    end
    if result.success == true then
      terminalFinish("success", translated("panel.success"))
    elseif result.retry == true then
      active.phase = "ready"
      lifecycle.phase = "ready"
      persistLifecycle()
      publish(active.id, active.title, active.prompt, active.confirmOnly, "ready", translated("panel.incorrect_password"))
      requestPanelOpen()
    else
      terminalFinish("failed", translated("panel.unlock_failed"))
    end
  end)
  if started == false then
    polling = false
    bridgeFailure()
  end
end

function onIpc(event, payload)
  if event ~= "keyring_request" or not validId(payload) then return end
  enqueueRequest(payload)
  startNextRequest()
end

function onExit()
  generation = generation + 1
  active = nil
  pendingId = nil
  fetching = false
  posting = false
  polling = false
  bridgeToken = nil
  bridgeBaseUrl = nil
  encodedBody = nil
  postAction = nil
end

local function sameLifecycle(left, right)
  if type(left) ~= "table" or left.version ~= right.version or left.active_id ~= right.active_id
    or left.phase ~= right.phase or type(left.queue) ~= "table" or #left.queue ~= #right.queue then return false end
  local fields = 0
  for key, _ in pairs(left) do
    if key ~= "version" and key ~= "active_id" and key ~= "phase" and key ~= "queue" then return false end
    fields = fields + 1
  end
  if fields ~= 4 then return false end
  for index, id in ipairs(right.queue) do
    if left.queue[index] ~= id then return false end
  end
  return true
end

local function sanitizeLifecycle(value)
  local sanitized = {version = 1, active_id = "", phase = "", queue = {}}
  local seen = {}
  local droppedActiveId = type(value) == "table" and type(value.active_id) == "string" and value.active_id or ""
  if type(value) == "table" and value.version == 1 and validId(value.active_id)
    and (value.phase == "fetching" or value.phase == "ready" or value.phase == "busy") then
    local descriptor = loadDescriptor(value.active_id)
    if descriptor ~= nil then
      sanitized.active_id = value.active_id
      sanitized.phase = value.phase
      seen[value.active_id] = true
      descriptor.token = nil
      descriptor.base_url = nil
      descriptor = nil
      droppedActiveId = ""
    end
  end
  if type(value) == "table" and type(value.queue) == "table" then
    for _, id in ipairs(value.queue) do
      if validId(id) and not seen[id] then
        local descriptor = loadDescriptor(id)
        if descriptor ~= nil then
          table.insert(sanitized.queue, id)
          seen[id] = true
          descriptor.token = nil
          descriptor.base_url = nil
          descriptor = nil
        end
      end
    end
  end
  return sanitized, not sameLifecycle(value, sanitized), droppedActiveId
end

local restored = noctalia.state.get("service_lifecycle")
local sanitized, lifecycleChanged, droppedActiveId = sanitizeLifecycle(restored)
lifecycle = sanitized
sanitized = nil
if droppedActiveId ~= "" then
  clearMatchingCommand(droppedActiveId)
  clearMatchingAuth(droppedActiveId)
end
restored = nil
if lifecycleChanged then
  persistLifecycle()
end
if lifecycle.active_id ~= "" then
  openRequest(lifecycle.active_id, lifecycle.phase)
else
  startNextRequest()
end
noctalia.setUpdateInterval(250)
