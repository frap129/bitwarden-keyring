--!nonstrict

local auth = nil
local password = ""
local inputKey = 0
local inputAccepting = false
local handlePasswordChange
local handleUnlock

local function newInstanceId()
  local characters = {}
  for index = 1, 32 do
    characters[index] = string.format("%x", math.random(0, 15))
  end
  return table.concat(characters)
end

local panelOpen = false
local panelRequestId = nil
local panelInstanceId = newInstanceId()

local function clearPassword()
  inputAccepting = false
  password = ""
  inputKey = inputKey + 1
end

local function validPhase(value)
  return value == "ready" or value == "busy" or value == "success" or value == "cancelled"
    or value == "confirmed" or value == "failed"
end

local function sanitizeAuth(value)
  if type(value) ~= "table" or type(value.id) ~= "string" or type(value.title) ~= "string"
    or type(value.prompt) ~= "string" or type(value.confirm_only) ~= "boolean"
    or type(value.phase) ~= "string" or not validPhase(value.phase) or type(value.error) ~= "string" then
    return nil
  end
  return {
    id = value.id,
    title = value.title,
    prompt = value.prompt,
    confirm_only = value.confirm_only,
    phase = value.phase,
    error = value.error,
  }
end

local function terminalText()
  if auth == nil then return noctalia.tr("panel.invalid_request") end
  if auth.error ~= "" then return auth.error end
  if auth.phase == "success" or auth.phase == "confirmed" then return noctalia.tr("panel.success") end
  if auth.phase == "cancelled" then return noctalia.tr("panel.cancelled") end
  if auth.phase == "failed" then return noctalia.tr("panel.unlock_failed") end
  if auth.phase == "busy" then return noctalia.tr("panel.unlocking") end
  return ""
end

local function terminalPhase(phase)
  return phase == "failed" or phase == "success" or phase == "cancelled" or phase == "confirmed"
end

local function requestProgrammaticDismiss()
  panel.close()
end

local function writePanelMarker()
  if not panelOpen or panelRequestId == nil then return end
  noctalia.state.set("panel_open", {
    id = panelRequestId,
    instance = panelInstanceId,
    heartbeat = os.time(),
  })
end

local function refreshOwnedPanelMarker(requestId, instanceId)
  local current = noctalia.state.get("panel_open")
  if type(current) == "table" and current.id == requestId and current.instance == instanceId then
    writePanelMarker()
  end
  current = nil
end

local function clearOwnedPanelMarker(requestId, instanceId)
  local current = noctalia.state.get("panel_open")
  if type(current) == "table" and current.id == requestId and current.instance == instanceId then
    noctalia.state.set("panel_open", false)
  end
  current = nil
end

function render()
  inputAccepting = false
  local title = noctalia.tr("panel.title")
  local prompt = ""
  local errorText = ""
  local confirmOnly = false
  local ready = false
  local busy = false
  if auth ~= nil then
    if auth.title ~= "" then title = auth.title end
    prompt = auth.prompt
    errorText = terminalText()
    confirmOnly = auth.confirm_only
    ready = auth.phase == "ready"
    busy = auth.phase == "busy"
  end

  local icon
  if noctalia.getConfig("show_bitwarden_icon") == true then
    icon = ui.image({ path = "assets/bitwarden.svg", width = 48, height = 48, fit = "contain" })
  else
    icon = ui.glyph({ name = "lock" })
  end

  local children = {
    icon,
    ui.label({ text = title }),
    ui.label({ text = prompt }),
  }
  if auth ~= nil and not confirmOnly then
    if ready then inputAccepting = true end
    local capturedInputKey = inputKey
    local capturedId = auth.id
    table.insert(children, ui.input({
      key = "password-" .. inputKey,
      value = "",
      placeholder = noctalia.tr("panel.password_placeholder"),
      password = true,
      focus = true,
      enabled = auth.phase == "ready",
      onChange = function(value)
        handlePasswordChange(value, capturedInputKey, capturedId)
      end,
      onSubmit = function()
        handleUnlock(capturedInputKey, capturedId)
      end,
    }))
  end
  table.insert(children, ui.label({ text = errorText }))
  if auth == nil then
    table.insert(children, ui.button({ text = noctalia.tr("panel.cancel"), enabled = true, onClick = "onInvalidDismiss" }))
  elseif terminalPhase(auth.phase) then
    table.insert(children, ui.button({ text = noctalia.tr("panel.cancel"), enabled = true, onClick = "onDismiss" }))
  elseif auth.phase == "ready" or auth.phase == "busy" or auth.phase == "cancelling" then
    local actions = {
      ui.button({ text = noctalia.tr("panel.cancel"), enabled = ready, onClick = "onCancel" }),
    }
    if confirmOnly then
      table.insert(actions, ui.button({ text = noctalia.tr("panel.confirm"), enabled = ready, onClick = "onConfirm" }))
    else
      table.insert(actions, ui.button({
        text = busy and noctalia.tr("panel.unlocking") or noctalia.tr("panel.unlock"),
        enabled = ready and password ~= "",
        onClick = "onUnlock",
      }))
    end
    table.insert(children, ui.row({ gap = 8 }, actions))
  end
  return ui.column({ gap = 12 }, children)
end

local function rerender()
  panel.render(render())
end

function handlePasswordChange(value, capturedInputKey, capturedId)
  if capturedInputKey ~= inputKey or auth == nil or capturedId ~= auth.id then return end
  if not inputAccepting or auth.phase ~= "ready" or auth.confirm_only then return end
  if type(value) ~= "string" then return end
  password = value
  rerender()
end

function handleUnlock(capturedInputKey, capturedId)
  if capturedInputKey ~= inputKey or auth == nil or capturedId ~= auth.id then return end
  if not inputAccepting or auth.phase ~= "ready" or auth.confirm_only then return end
  onUnlock()
end

function onUnlock()
  if auth == nil or auth.phase ~= "ready" or auth.confirm_only or password == "" then return end
  local submitted = password
  clearPassword()
  auth.phase = "busy"
  noctalia.state.set("command", { action = "submit", id = auth.id, password = submitted })
  submitted = nil
  rerender()
end

function onConfirm()
  if auth == nil or auth.phase ~= "ready" or not auth.confirm_only then return end
  clearPassword()
  auth.phase = "busy"
  noctalia.state.set("command", { action = "confirm", id = auth.id })
  rerender()
end

function onCancel()
  if auth == nil or auth.phase ~= "ready" then return end
  clearPassword()
  auth.phase = "cancelling"
  noctalia.state.set("command", { action = "cancel", id = auth.id })
  rerender()
  if noctalia.getConfig("auto_close_on_cancel") == true then requestProgrammaticDismiss() end
end

function onDismiss()
  if auth == nil or not terminalPhase(auth.phase) then return end
  clearPassword()
  requestProgrammaticDismiss()
end

function onInvalidDismiss()
  if auth ~= nil then return end
  clearPassword()
  requestProgrammaticDismiss()
end

function onOpen()
  clearPassword()
  auth = sanitizeAuth(noctalia.state.get("auth"))
  panelOpen = true
  panelRequestId = auth ~= nil and auth.id or nil
  if panelRequestId ~= nil then
    writePanelMarker()
  end
  rerender()
end

function update()
  refreshOwnedPanelMarker(panelRequestId, panelInstanceId)
end

function onClose()
  local closingRequestId = panelRequestId
  local closingInstanceId = panelInstanceId
  panelOpen = false
  panelRequestId = nil
  clearPassword()
  clearOwnedPanelMarker(closingRequestId, closingInstanceId)
end

function onAuthChanged(value)
  inputAccepting = false
  if value == false then
    local ownedRequestId = panelRequestId
    clearPassword()
    auth = nil
    if panelOpen then
      panelRequestId = nil
      clearOwnedPanelMarker(ownedRequestId, panelInstanceId)
    end
    rerender()
    return
  end
  local ownedRequestId = panelRequestId
  local nextAuth = sanitizeAuth(value)
  if nextAuth == nil then
    clearPassword()
    auth = nil
    if panelOpen then
      panelRequestId = nil
      clearOwnedPanelMarker(ownedRequestId, panelInstanceId)
    end
    rerender()
    return
  end
  clearPassword()
  auth = nextAuth
  if panelOpen then
    panelRequestId = auth.id
    refreshOwnedPanelMarker(ownedRequestId, panelInstanceId)
  end
  rerender()
  if auth.phase == "cancelled" then
    if noctalia.getConfig("auto_close_on_cancel") == true then requestProgrammaticDismiss() end
  elseif auth.phase == "success" or auth.phase == "confirmed" then
    if noctalia.getConfig("auto_close_on_success") == true then requestProgrammaticDismiss() end
  end
end

noctalia.state.watch("auth", onAuthChanged)
noctalia.setUpdateInterval(1000)
