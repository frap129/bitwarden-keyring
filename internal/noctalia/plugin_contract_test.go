package noctalia

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

type pluginManifest struct {
	root     map[string]any
	services []map[string]any
	panels   []map[string]any
	settings []map[string]any
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
}

func TestV5PluginCatalogContract(t *testing.T) {
	root := repositoryRoot(t)
	contents, err := os.ReadFile(filepath.Join(root, "catalog.toml"))
	if err != nil {
		t.Fatalf("read catalog.toml: %v", err)
	}
	plugins, err := parsePluginCatalog(string(contents))
	if err != nil {
		t.Fatalf("parse catalog.toml: %v", err)
	}
	want := map[string]any{
		"id": "frap129/noctalia-bitwarden-keyring", "name": "Bitwarden Keyring", "version": "0.5.0",
		"author": "frap129", "license": "MIT", "icon": "brand-bitwarden",
		"description": "Secure prompts for the Bitwarden-backed Secret Service and SSH agent.",
		"deprecated":  false, "plugin_api": 16, "tags": []string{"bitwarden", "password", "security"},
		"dependencies": []string{"bitwarden-keyring"},
	}
	if len(plugins) != 1 || !reflect.DeepEqual(plugins[0], want) {
		t.Fatalf("catalog plugins = %#v, want one plugin %#v", plugins, want)
	}

	manifestContents, err := os.ReadFile(filepath.Join(root, "noctalia-bitwarden-keyring", "plugin.toml"))
	if err != nil {
		t.Fatalf("read plugin.toml: %v", err)
	}
	manifest, err := parsePluginManifest(string(manifestContents))
	if err != nil {
		t.Fatalf("parse plugin.toml: %v", err)
	}
	for _, key := range []string{"id", "name", "version", "author", "license", "icon", "description", "plugin_api", "tags", "dependencies"} {
		if !reflect.DeepEqual(plugins[0][key], manifest.root[key]) {
			t.Errorf("catalog %s = %#v, manifest = %#v", key, plugins[0][key], manifest.root[key])
		}
	}

	if _, err := os.Lstat(filepath.Join(root, "registry.json")); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			t.Error("registry.json still exists")
		} else {
			t.Errorf("registry.json absence: %v", err)
		}
	}
}

func parsePluginCatalog(source string) ([]map[string]any, error) {
	allowed := keySet("id", "name", "version", "author", "license", "icon", "description", "deprecated", "plugin_api", "tags", "dependencies")
	var plugins []map[string]any
	var current map[string]any
	for lineNumber, rawLine := range strings.Split(source, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if line != "[[plugin]]" {
				return nil, fmt.Errorf("line %d: invalid table header %q", lineNumber+1, line)
			}
			current = make(map[string]any)
			plugins = append(plugins, current)
			continue
		}
		if current == nil {
			return nil, fmt.Errorf("line %d: content before plugin table", lineNumber+1)
		}
		key, rawValue, found := strings.Cut(line, "=")
		key, rawValue = strings.TrimSpace(key), strings.TrimSpace(rawValue)
		if !found || key == "" || rawValue == "" {
			return nil, fmt.Errorf("line %d: malformed assignment", lineNumber+1)
		}
		if !allowed[key] {
			return nil, fmt.Errorf("line %d: unknown plugin key %q", lineNumber+1, key)
		}
		if _, duplicate := current[key]; duplicate {
			return nil, fmt.Errorf("line %d: duplicate plugin key %q", lineNumber+1, key)
		}
		value, err := parseManifestValue(rawValue)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber+1, err)
		}
		current[key] = value
	}
	return plugins, nil
}

func TestV5PluginSourceContract(t *testing.T) {
	pluginDir := filepath.Join(repositoryRoot(t), "noctalia-bitwarden-keyring")

	available := make(map[string]bool)
	for _, name := range []string{"plugin.toml", "service.luau", "panel.luau", filepath.Join("translations", "en.json")} {
		info, err := os.Stat(filepath.Join(pluginDir, name))
		if err != nil {
			t.Errorf("required plugin file %s: %v", name, err)
			continue
		}
		if !info.Mode().IsRegular() {
			t.Errorf("required plugin file %s is not regular", name)
			continue
		}
		available[name] = true
	}

	for _, name := range []string{"manifest.json", "Main.qml", "Panel.qml", "AuthDialog.qml", "Settings.qml"} {
		if _, err := os.Lstat(filepath.Join(pluginDir, name)); err == nil {
			t.Errorf("legacy plugin file %s still exists", name)
		} else if !os.IsNotExist(err) {
			t.Errorf("check legacy plugin file %s: %v", name, err)
		}
	}

	for _, name := range []string{"service.luau", "panel.luau"} {
		if !available[name] {
			continue
		}
		contents, err := os.ReadFile(filepath.Join(pluginDir, name))
		if err != nil {
			t.Errorf("read required plugin file %s: %v", name, err)
			continue
		}
		source := string(contents)
		if !strings.Contains(source, "--!nonstrict") {
			t.Errorf("%s does not contain --!nonstrict", name)
		}
		for _, forbidden := range []string{"pluginApi", "SocketServer", "Quickshell", "print(", "runAsync", "runStream"} {
			if strings.Contains(source, forbidden) {
				t.Errorf("%s contains forbidden literal %q", name, forbidden)
			}
		}
	}

	if available["service.luau"] {
		contents, err := os.ReadFile(filepath.Join(pluginDir, "service.luau"))
		if err != nil {
			t.Errorf("read required plugin file service.luau: %v", err)
		} else {
			assertServiceSource(t, string(contents))
		}
	}

	if available["panel.luau"] {
		contents, err := os.ReadFile(filepath.Join(pluginDir, "panel.luau"))
		if err != nil {
			t.Errorf("read required plugin file panel.luau: %v", err)
		} else {
			assertPanelSource(t, string(contents))
		}
	}

	if available["plugin.toml"] {
		contents, err := os.ReadFile(filepath.Join(pluginDir, "plugin.toml"))
		if err != nil {
			t.Errorf("read required plugin file plugin.toml: %v", err)
		} else if manifest, err := parsePluginManifest(string(contents)); err != nil {
			t.Errorf("parse plugin.toml: %v", err)
		} else {
			assertPluginManifest(t, manifest)
		}
	}

	translationName := filepath.Join("translations", "en.json")
	if available[translationName] {
		contents, err := os.ReadFile(filepath.Join(pluginDir, translationName))
		if err != nil {
			t.Errorf("read required plugin file %s: %v", translationName, err)
		} else {
			assertTranslations(t, contents)
		}
	}
	if available["service.luau"] && available["panel.luau"] && available[translationName] {
		serviceContents, serviceErr := os.ReadFile(filepath.Join(pluginDir, "service.luau"))
		panelContents, panelErr := os.ReadFile(filepath.Join(pluginDir, "panel.luau"))
		translationContents, translationErr := os.ReadFile(filepath.Join(pluginDir, translationName))
		if serviceErr == nil && panelErr == nil && translationErr == nil {
			assertTranslationReferences(t, string(serviceContents)+"\n"+string(panelContents), translationContents)
		}
	}
}

func TestV5PluginDocumentationParsesThreeFieldSourceList(t *testing.T) {
	root := repositoryRoot(t)
	for _, name := range []string{"README.md", filepath.Join("noctalia-bitwarden-keyring", "README.md")} {
		contents, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(contents)
		if !strings.Contains(text, `grep -Fqx "bitwarden-keyring path $PWD"`) {
			t.Errorf("%s does not match Noctalia's name/type/location source format", name)
		}
		if strings.Contains(text, "noctalia msg plugins source list\nsources=") {
			t.Errorf("%s prints unrelated plugin sources", name)
		}
	}
}

func assertTranslationReferences(t *testing.T, source string, contents []byte) {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(contents, &document); err != nil {
		return
	}
	references := regexp.MustCompile(`noctalia\.tr\("([^"]+)"\)`).FindAllStringSubmatch(source, -1)
	for _, reference := range references {
		var current any = document
		for _, segment := range strings.Split(reference[1], ".") {
			object, ok := current.(map[string]any)
			if !ok {
				t.Errorf("source translation %q does not resolve to a nested string", reference[1])
				break
			}
			current, ok = object[segment]
			if !ok {
				t.Errorf("source translation %q does not resolve", reference[1])
				break
			}
		}
		if _, ok := current.(string); !ok {
			t.Errorf("source translation %q does not resolve to a string", reference[1])
		}
	}
}

func assertPanelSource(t *testing.T, source string) {
	t.Helper()
	for _, required := range []string{
		`--!nonstrict`, `local auth`, `local password`, `local inputKey`, `local inputAccepting`,
		`local panelOpen = false`, `local panelRequestId = nil`, `local panelInstanceId = newInstanceId()`,
		`function render()`, `ui.label({ text = title })`, `ui.label({ text = prompt })`, `ui.input({`,
		`ui.glyph({ name = "lock" })`, `ui.image({ path = "assets/bitwarden.svg", width = 48, height = 48, fit = "contain" })`, `ui.column({ gap = 12 }, children)`,
		`noctalia.getConfig("show_bitwarden_icon")`,
		`key = "password-" .. inputKey`, `value = ""`, `password = true`, `focus = true`, `enabled = auth.phase == "ready"`,
		`local capturedInputKey = inputKey`, `local capturedId = auth.id`, `onChange = function(value)`, `onSubmit = function()`,
		`handlePasswordChange(value, capturedInputKey, capturedId)`, `handleUnlock(capturedInputKey, capturedId)`, `panel.render(render())`,
		`function onOpen()`, `function update()`, `function onClose()`, `panel.close()`, `noctalia.setUpdateInterval(1000)`,
		`id = panelRequestId`, `instance = panelInstanceId`, `heartbeat = os.time()`,
		`value.id`, `value.title`, `value.prompt`, `value.confirm_only`, `value.phase`, `value.error`,
		`action = "submit"`, `action = "cancel"`, `action = "confirm"`,
		`submitted = nil`, `password = ""`, `inputKey = inputKey + 1`,
		`noctalia.getConfig("auto_close_on_cancel")`, `noctalia.getConfig("auto_close_on_success")`,
		`noctalia.state.watch("auth", onAuthChanged)`,
		`if capturedInputKey ~= inputKey or auth == nil or capturedId ~= auth.id then return end`,
		`if not inputAccepting or auth.phase ~= "ready" or auth.confirm_only then return end`,
		`if auth == nil or not terminalPhase(auth.phase) then return end`,
		`ui.row({ gap = 8 }, actions)`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("panel.luau does not contain required literal %q", required)
		}
	}
	for _, action := range []string{`onClick = "onCancel"`, `onClick = "onUnlock"`, `onClick = "onConfirm"`} {
		if !strings.Contains(source, action) {
			t.Errorf("panel.luau does not contain named command callback %q", action)
		}
	}
	if !strings.Contains(source, `onClick = "onDismiss"`) {
		t.Error("panel.luau terminal failure is not dismissible with a named callback")
	}
	for _, forbidden := range []string{
		"frameTick", "onFrame", "setTimeout", "setInterval", "animation", "timer", "geometry",
		"pluginSettings", "openPanel", "closePanel", "saveSettings",
		"pluginApi", "SocketServer", "Quickshell", "runAsync", "runStream", "print(",
		"ui.text(", "ui.textInput(", "source =", "children = children",
	} {
		if strings.Contains(source, forbidden) {
			t.Errorf("panel.luau contains forbidden literal %q", forbidden)
		}
	}
	if regexp.MustCompile(`(?s)noctalia\.state\.set\("auth"[^\n]*(password)|auth\s*=\s*\{[^}]*password`).MatchString(source) {
		t.Error("panel.luau places a password in shared auth state")
	}
	if !regexp.MustCompile(`(?s)local function clearPassword\(\)\s+inputAccepting = false\s+password = ""\s+inputKey = inputKey \+ 1`).MatchString(source) {
		t.Error("panel.luau must stop accepting input before clearing and incrementing its key")
	}
	if !regexp.MustCompile(`(?s)function onAuthChanged\(value\)\s+inputAccepting = false`).MatchString(source) {
		t.Error("panel.luau auth watch must synchronously stop accepting stale input")
	}
	if !regexp.MustCompile(`(?s)local nextAuth = sanitizeAuth\(value\).*?if nextAuth == nil then.*?end\s+clearPassword\(\)\s+auth = nextAuth`).MatchString(source) {
		t.Error("panel.luau must clear password and increment its key for every valid auth update")
	}
	if !regexp.MustCompile(`(?s)function onDismiss\(\)\s+if auth == nil or not terminalPhase\(auth\.phase\) then return end\s+clearPassword\(\)\s+requestProgrammaticDismiss\(\)`).MatchString(source) {
		t.Error("panel.luau dismiss must validate the current terminal auth before suppressing close")
	}
	if !regexp.MustCompile(`(?s)function onInvalidDismiss\(\)\s+if auth ~= nil then return end\s+clearPassword\(\)\s+requestProgrammaticDismiss\(\)`).MatchString(source) {
		t.Error("panel.luau invalid-state dismiss must not close or suppress a valid request")
	}
	if !strings.Contains(source, `onClick = "onInvalidDismiss"`) {
		t.Error("panel.luau invalid state is not dismissible")
	}
	for _, callback := range []string{`onClick = "onInvalidDismiss"`, `onClick = "onDismiss"`, `onClick = "onCancel"`, `onClick = "onUnlock"`, `onClick = "onConfirm"`} {
		if strings.Count(source, callback) != 1 {
			t.Errorf("panel.luau action callback %q must have exactly one render path", callback)
		}
	}
	actionBranches := regexp.MustCompile(`(?s)if auth == nil then\s+table\.insert\(children, ui\.button\(\{[^}]*onClick = "onInvalidDismiss"[^}]*\}\)\)\s+elseif terminalPhase\(auth\.phase\) then\s+table\.insert\(children, ui\.button\(\{[^}]*onClick = "onDismiss"[^}]*\}\)\)\s+elseif auth\.phase == "ready" or auth\.phase == "busy" or auth\.phase == "cancelling" then(.*?)table\.insert\(children, ui\.row\(\{ gap = 8 \}, actions\)\)\s+end`)
	branchMatch := actionBranches.FindStringSubmatch(source)
	if len(branchMatch) != 2 {
		t.Error("panel.luau must render invalid, terminal, and normal actions as mutually exclusive branches")
	} else {
		for _, callback := range []string{`onClick = "onCancel"`, `onClick = "onUnlock"`, `onClick = "onConfirm"`} {
			if !strings.Contains(branchMatch[1], callback) {
				t.Errorf("panel.luau normal action row does not contain %q", callback)
			}
		}
	}
	if !regexp.MustCompile(`(?s)function onClose\(\)\s+local closingRequestId = panelRequestId\s+local closingInstanceId = panelInstanceId.*?clearOwnedPanelMarker\(closingRequestId, closingInstanceId\)`).MatchString(source) {
		t.Error("panel.luau close must clear only its immutable ID and instance marker")
	}
	if !regexp.MustCompile(`(?s)local function newInstanceId\(\).*?for index = 1, 32 do.*?string\.format\("%x", math\.random\(0, 15\)\)`).MatchString(source) {
		t.Error("panel.luau must create a fresh random 32-lowercase-hex instance ID")
	}
	if !strings.Contains(source, `local function clearOwnedPanelMarker(requestId, instanceId)`) || strings.Count(source, `clearOwnedPanelMarker(`) < 3 {
		t.Error("panel.luau must ownership-guard close and auth marker clearing")
	}
	if !strings.Contains(source, `local function refreshOwnedPanelMarker(requestId, instanceId)`) || strings.Count(source, `refreshOwnedPanelMarker(`) < 3 {
		t.Error("panel.luau must ownership-guard heartbeat and auth marker updates")
	}
	closeCallback := regexp.MustCompile(`(?s)function onClose\(\)(.*?)\nend`).FindStringSubmatch(source)
	if len(closeCallback) != 2 || strings.Contains(closeCallback[1], `state.set("command"`) || strings.Contains(closeCallback[1], `action = "cancel"`) {
		t.Error("panel.luau onClose must never publish cancellation")
	}
	if strings.Count(source, `capturedInputKey ~= inputKey or auth == nil or capturedId ~= auth.id`) != 2 {
		t.Error("panel.luau must generation- and ID-guard both input callbacks")
	}
	inputCallbacks := regexp.MustCompile(`(?s)onChange = function\(value\)(.*?)end,\s+onSubmit = function\(\)(.*?)end,`).FindStringSubmatch(source)
	if len(inputCallbacks) != 3 {
		t.Error("panel.luau must define inspectable inline input callbacks")
	} else if strings.Contains(inputCallbacks[1], "password") || strings.Contains(inputCallbacks[2], "password") {
		t.Error("panel.luau input closures must not capture or access password values")
	}
}

type panelCallbackModel struct {
	authComplete, inputAccepting, confirmOnly bool
	inputKey                                  int
	authID                                    string
	phase                                     string
	password                                  string
	closed, suppressed                        bool
	submitted                                 bool
	commands                                  int
}

func (m *panelCallbackModel) authUpdate() {
	m.inputAccepting = false
	m.password = ""
	m.inputKey++
}

func (m *panelCallbackModel) close() {
	m.password = ""
	m.inputKey++
	m.suppressed = false
}

func (m *panelCallbackModel) invalidDismiss() {
	if m.authComplete {
		return
	}
	m.suppressed = true
	m.closed = true
}

func TestPanelModelSameAuthUpdateClearsAndIncrements(t *testing.T) {
	model := panelCallbackModel{authComplete: true, inputAccepting: true, inputKey: 4, authID: "same", phase: "ready", password: "secret"}
	model.authUpdate()
	if model.password != "" || model.inputKey != 5 || model.inputAccepting {
		t.Fatalf("same-ID auth update retained input state: %#v", model)
	}
}

func TestPanelModelRepeatedCloseNeverCancels(t *testing.T) {
	model := panelCallbackModel{authComplete: true, inputKey: 2, phase: "ready", password: "secret"}
	model.close()
	model.close()
	if model.commands != 0 || model.phase != "ready" || model.password != "" || model.inputKey != 4 {
		t.Fatalf("repeated close lifecycle = %#v", model)
	}
}

func TestPanelModelInvalidDismissRejectsCurrentAuth(t *testing.T) {
	model := panelCallbackModel{authComplete: true, phase: "ready"}
	model.invalidDismiss()
	if model.closed || model.suppressed {
		t.Fatalf("stale invalid dismiss changed valid auth: %#v", model)
	}
}

func (m *panelCallbackModel) unlock(capturedInputKey int, capturedID string) {
	if capturedInputKey != m.inputKey || capturedID != m.authID || !m.inputAccepting || !m.authComplete || m.phase != "ready" || m.confirmOnly || m.password == "" {
		return
	}
	m.submitted = true
}

func (m *panelCallbackModel) passwordChange(value any, capturedInputKey int, capturedID string) {
	text, ok := value.(string)
	if !ok || capturedInputKey != m.inputKey || capturedID != m.authID || !m.inputAccepting || !m.authComplete || m.phase != "ready" || m.confirmOnly {
		return
	}
	m.password = text
}

func TestPanelModelRejectsStaleUnlocks(t *testing.T) {
	for _, fixture := range []struct {
		capturedInputKey  int
		capturedRequestID string
	}{
		{capturedInputKey: 40, capturedRequestID: "new"},
		{capturedInputKey: 41, capturedRequestID: "old"},
	} {
		model := panelCallbackModel{authComplete: true, inputAccepting: true, inputKey: 41, authID: "new", phase: "ready", password: "current"}
		model.unlock(fixture.capturedInputKey, fixture.capturedRequestID)
		if model.submitted {
			t.Fatalf("stale input submitted current request: %#v", model)
		}
	}
}

func (m *panelCallbackModel) dismiss() {
	if !m.authComplete || m.phase != "failed" {
		return
	}
	m.suppressed = true
	m.closed = true
}

func TestPanelModelRejectsStalePasswordChanges(t *testing.T) {
	for _, fixture := range []struct {
		model             panelCallbackModel
		capturedInputKey  int
		capturedRequestID string
	}{
		{model: panelCallbackModel{authComplete: true, inputAccepting: true, inputKey: 9, authID: "new", phase: "ready"}, capturedInputKey: 8, capturedRequestID: "new"},
		{model: panelCallbackModel{authComplete: true, inputAccepting: true, inputKey: 9, authID: "new", phase: "ready"}, capturedInputKey: 9, capturedRequestID: "old"},
		{model: panelCallbackModel{authComplete: true, inputAccepting: true, inputKey: 9, authID: "new", phase: "busy"}, capturedInputKey: 9, capturedRequestID: "new"},
		{model: panelCallbackModel{authComplete: true, inputAccepting: true, inputKey: 9, authID: "new", phase: "ready", confirmOnly: true}, capturedInputKey: 9, capturedRequestID: "new"},
	} {
		fixture.model.passwordChange("stale", fixture.capturedInputKey, fixture.capturedRequestID)
		if fixture.model.password != "" {
			t.Fatalf("stale password callback restored password: %#v", fixture.model)
		}
	}
}

func TestPanelModelDismissesOnlyCurrentFailure(t *testing.T) {
	for _, phase := range []string{"ready", "busy"} {
		model := panelCallbackModel{authComplete: true, phase: phase}
		model.dismiss()
		if model.closed || model.suppressed {
			t.Fatalf("stale dismiss changed %s state: %#v", phase, model)
		}
	}
}

func assertServiceSource(t *testing.T, source string) {
	t.Helper()
	for _, required := range []string{
		`--!nonstrict`, `noctalia.getenv("XDG_RUNTIME_DIR")`, `noctalia.readFile`,
		`"Authorization: Bearer " .. token`, `"Accept: application/json"`, `"Cache-Control: no-store"`,
		`table.insert(headers, "Content-Type: application/json")`, `/v1/request`, `/v1/response`, `/v1/result`,
		`noctalia.setUpdateInterval(250)`, `function update()`, `capturedGeneration ~= generation`,
		`capturedId ~= pendingId`, `capturedId ~= active.id`, `status ~= 200 and status ~= 204 and status ~= 409`,
		`noctalia.state.set("command", nil)`, `noctalia.state.set("auth", false)`, `noctalia.state.get("panel_open")`,
		`id = id`, `title = title`, `prompt = prompt`, `confirm_only = confirmOnly`, `phase = phase`, `error = errorText`,
		`value.password = nil`, `wire.password = nil`, `body = nil`,
		`value.retry == nil or type(value.retry) == "boolean"`, `local terminal = {`,
		`noctalia.state.set("auth", terminal)`, `local showPanel = owner == nil and validId(pendingId)`,
		`(action == "submit" and active.confirmOnly == true)`,
		`local processingCommand = false`, `local postAction = nil`, `if processingCommand then return end`, `if postAction ~= nil then return end`,
		`if type(value) ~= "table" then return end`, `local retainedCommand = noctalia.state.get("command")`,
		`onCommand(retainedCommand)`, `status ~= 202 and status ~= 409 and status ~= 410`,
		`local commandIdentity = 0`, `commandIdentity = commandIdentity + 1`, `local capturedCommandIdentity = commandIdentity`, `local capturedAction = action`,
		`local lifecycle = {version = 1, active_id = "", phase = "", queue = {}}`,
		`local function persistLifecycle()`, `noctalia.state.set("service_lifecycle", snapshot)`,
		`local function enqueueRequest(id)`, `startNextRequest = function()`, `local function terminalFinish(`,
		`enqueueRequest(payload)`, `startNextRequest()`, `noctalia.state.get("service_lifecycle")`,
		`local panelOpeningFor = nil`, `local panelOpeningAt = 0`, `heartbeat >= now - 3`,
		`panelOpeningAt = now`, `now - panelOpeningAt < 1`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("service.luau does not contain required literal %q", required)
		}
	}
	if strings.Contains(source, `os.clock`) {
		t.Error("service.luau panel opening guard must use wall-clock seconds, not os.clock")
	}
	if regexp.MustCompile(`(?s)function onIpc\(event, payload\).*?active ~= nil.*?return`).MatchString(source) {
		t.Error("service.luau onIpc must enqueue occupied requests instead of returning early")
	}
	if !regexp.MustCompile(`(?s)local function activeDescriptorExists\(\)\s+local id = lifecycle\.active_id\s+if id == "" then return true end`).MatchString(source) {
		t.Error("service.luau update must validate persisted active ownership before any retry, poll, or open logic")
	}
	if regexp.MustCompile(`(?s)state\.set\("service_lifecycle",\s*\{[^}]*?(token|url|path|password|body|title|prompt|error)`).MatchString(strings.ToLower(source)) {
		t.Error("service.luau lifecycle state contains sensitive or presentation data")
	}
	snapshotMatch := regexp.MustCompile(`local snapshot = \{([^}]*)\}`).FindStringSubmatch(source)
	if len(snapshotMatch) != 2 {
		t.Error("service.luau must define an inspectable lifecycle snapshot initializer")
	} else {
		keys := regexp.MustCompile(`([a-z_]+)\s*=`).FindAllStringSubmatch(snapshotMatch[1], -1)
		got := make([]string, 0, len(keys))
		for _, key := range keys {
			got = append(got, key[1])
		}
		if want := []string{"version", "active_id", "phase", "queue"}; !reflect.DeepEqual(got, want) {
			t.Errorf("service.luau lifecycle snapshot keys = %#v, want exact %#v", got, want)
		}
	}
	if !regexp.MustCompile(`(?s)for key, _ in pairs\(left\.queue\) do.*?type\(key\) ~= "number".*?key < 1.*?key % 1 ~= 0.*?key > #right\.queue`).MatchString(source) {
		t.Error("service.luau must reject non-array, sparse, and noninteger lifecycle queue keys")
	}
	startupLifecycle := strings.Index(source, `noctalia.state.get("service_lifecycle")`)
	if startupLifecycle < 0 || strings.Contains(source[startupLifecycle:], `registerCommandWatcher()`) {
		t.Error("service.luau must sanitize and restore lifecycle before registering the command watcher")
	}
	for _, required := range []string{
		`local startupRecovering = true`, `local function finalizeStartupRecovery()`,
		`local retainedCommand = noctalia.state.get("command")`, `clearMatchingAuth(droppedActiveId)`,
		`if lifecycleChanged then`, `if phase == "busy" then`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("service.luau startup recovery does not contain required literal %q", required)
		}
	}
	getRetained := strings.Index(source, `local retainedCommand = noctalia.state.get("command")`)
	publishRehydrated := -1
	if getRetained >= 0 {
		publishRehydrated = strings.Index(source[getRetained:], `publish(active.id`)
	}
	if publishRehydrated < 0 {
		t.Error("service.luau must inspect retained command before publishing rehydrated auth")
	}
	if !regexp.MustCompile(`(?s)local recoveryGeneration = generation\s+local recoveryId = capturedId.*?onCommand\(retainedCommand\).*?if recoveryGeneration == generation and active ~= nil and recoveryId == active\.id`).MatchString(source) {
		t.Error("service.luau retained startup command must generation- and ID-guard mutable active state")
	}
	if strings.Count(source, `capturedGeneration ~= generation`) < 3 {
		t.Error("service.luau must generation-guard every HTTP callback")
	}
	if strings.Count(source, `capturedId ~=`) < 3 {
		t.Error("service.luau must ID-guard every HTTP callback")
	}
	terminalFunction := regexp.MustCompile(`(?s)local function terminalFinish\(.*?\nend`).FindString(source)
	publishTerminal := strings.Index(terminalFunction, `noctalia.state.set("auth", terminal)`)
	invalidateTerminal := strings.Index(terminalFunction, "invalidatePrivate()")
	if publishTerminal < 0 || invalidateTerminal < 0 || publishTerminal > invalidateTerminal {
		t.Error("service.luau must publish terminal auth before invalidating callbacks")
	}
	for _, forbidden := range []string{
		`Authorization =`, `["Cache-Control"]`, `headers["Content-Type"]`,
		`panel_open", nil`, `panel_open", false`, `panel_open", true`,
		"os.execute", "io.popen", "noctalia.exec", "noctalia.spawn", "console.log", "logger", "notify(", "noctalia.http.request",
		`publish(active.id, active.title, active.prompt, active.confirmOnly, "cancelling"`, `result.error`,
		`active.phase = postAction == "submit" and "busy" or "cancelling"`,
		`function ignoreExitResponse`, `pcall(noctalia.http, request, ignoreExitResponse)`,
		`function(res)
    body`, `function(res)
    token`, `function(res)
    baseUrl`, `activeRequest`,
	} {
		if strings.Contains(source, forbidden) {
			t.Errorf("service.luau contains forbidden literal %q", forbidden)
		}
	}
	if regexp.MustCompile(`(?s)onCommand = function\(value\)\s+if type\(value\) ~= "table" then return end`).FindString(source) == "" {
		t.Error("service.luau command watcher must immediately ignore non-table values")
	}
	if regexp.MustCompile(`(?s)if type\(value\) ~= "table" then\s+noctalia\.state\.set\("command", nil\)`).MatchString(source) {
		t.Error("service.luau command watcher recursively clears non-table values")
	}
	if !regexp.MustCompile(`(?s)processingCommand = true.*?value\.password = nil.*?noctalia\.state\.set\("command", nil\).*?value = nil.*?processingCommand = false`).MatchString(source) {
		t.Error("service.luau must guard and single-clear rejected or acknowledged commands")
	}
	if !regexp.MustCompile(`(?s)local function clearAcknowledgedCommand\(id, action, identity\).*?local current = noctalia\.state\.get\("command"\).*?if identity ~= commandIdentity or type\(current\) ~= "table" or current\.id ~= id or current\.action ~= action then return end.*?clearCommand\(current\)`).MatchString(source) {
		t.Error("service.luau acknowledgment must clear only the exact observed command identity")
	}
	if !regexp.MustCompile(`(?s)local capturedAction = action.*?clearAcknowledgedCommand\(capturedId, capturedAction, capturedCommandIdentity\)`).MatchString(source) {
		t.Error("service.luau acknowledgment must use captured ID, action, and monotonic identity")
	}
	onExit := regexp.MustCompile(`(?s)function onExit\(\)(.*?)\nend`).FindStringSubmatch(source)
	if len(onExit) != 2 {
		t.Error("service.luau must define inspectable onExit")
	} else if strings.Contains(onExit[1], `noctalia.state.set("command", nil)`) {
		t.Error("service.luau onExit must retain an unacknowledged shared command")
	} else {
		for _, cleared := range []string{"bridgeToken = nil", "bridgeBaseUrl = nil", "encodedBody = nil", "postAction = nil"} {
			if !strings.Contains(onExit[1], cleared) {
				t.Errorf("service.luau onExit does not clear private value %q", cleared)
			}
		}
		for _, forbiddenExit := range []string{"noctalia.http", "noctalia.state.set", "keyring_response", "cancelled", "clearCommand("} {
			if strings.Contains(onExit[1], forbiddenExit) {
				t.Errorf("service.luau onExit races retained commands via %q", forbiddenExit)
			}
		}
	}
	if regexp.MustCompile(`(?s)end\s+noctalia\.state\.set\("command", nil\)\s+noctalia\.state\.set\("auth", false\)\s+noctalia\.state\.watch\("command", onCommand\)`).MatchString(source) {
		t.Error("service.luau startup must retain an unacknowledged shared command")
	}
	if regexp.MustCompile(`(?i)url\s*=[^\n]*(token|password)`).MatchString(source) {
		t.Error("service.luau appears to place the token in a URL")
	}
	callbackPattern := regexp.MustCompile(`(?s)\}, function\(res\)\n(.*?)\n  end\)`)
	callbacks := callbackPattern.FindAllStringSubmatch(source, -1)
	if len(callbacks) != 3 {
		t.Errorf("service.luau HTTP callbacks = %d, want 3 inspectable callbacks", len(callbacks))
	}
	for _, callback := range callbacks {
		for _, capturedSecret := range []string{"token =", "baseUrl =", "body = nil", "descriptor"} {
			if strings.Contains(callback[1], capturedSecret) {
				t.Errorf("service.luau callback retains local secret via %q", capturedSecret)
			}
		}
	}
}

type serviceResultFixture struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Success bool   `json:"success"`
	Retry   *bool  `json:"retry"`
}

func validServiceResultFixture(value serviceResultFixture, id string) bool {
	return value.Type == "keyring_result" && value.ID == id
}

func TestServiceResultAcceptsTerminalJSONWithoutRetry(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef"
	var result serviceResultFixture
	if err := json.Unmarshal([]byte(`{"type":"keyring_result","id":"`+id+`","success":false}`), &result); err != nil {
		t.Fatal(err)
	}
	if !validServiceResultFixture(result, id) || result.Retry != nil {
		t.Fatalf("terminal result without retry rejected: %#v", result)
	}
}

const (
	requestIDA = "0123456789abcdef0123456789abcdef"
	requestIDB = "11111111111111111111111111111111"
	requestIDC = "22222222222222222222222222222222"
)

type serviceLifecycleFixture struct {
	Version  int
	ActiveID string
	Phase    string
	Queue    []string
}

type serviceLifecycleModel struct {
	state          serviceLifecycleFixture
	outcome        string
	pendingCommand string
	operation      string
	staleIDs       map[string]bool
}

func validRequestID(id string) bool {
	return regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(id)
}

func (m *serviceLifecycleModel) enqueue(id string) {
	if !validRequestID(id) || id == m.state.ActiveID {
		return
	}
	for _, queuedID := range m.state.Queue {
		if id == queuedID {
			return
		}
	}
	m.state.Queue = append(m.state.Queue, id)
}

func (m *serviceLifecycleModel) startNext() string {
	m.state.Version = 1
	m.state.ActiveID = ""
	m.state.Phase = ""
	for len(m.state.Queue) > 0 {
		id := m.state.Queue[0]
		m.state.Queue = m.state.Queue[1:]
		if !validRequestID(id) || m.staleIDs[id] {
			continue
		}
		m.state.ActiveID = id
		m.state.Phase = "fetching"
		return id
	}
	return ""
}

func (m *serviceLifecycleModel) finish(outcome string) string {
	m.outcome = outcome
	return m.startNext()
}

func (m *serviceLifecycleModel) restore() string {
	queue := m.state.Queue
	m.state.Queue = nil
	for _, id := range queue {
		if id != m.state.ActiveID && !m.staleIDs[id] {
			m.enqueue(id)
		}
	}
	validPhase := m.state.Phase == "fetching" || m.state.Phase == "ready" || m.state.Phase == "busy"
	validOwnership := m.state.Version == 1 && m.state.ActiveID != "" && validRequestID(m.state.ActiveID) && validPhase
	if validOwnership && !m.staleIDs[m.state.ActiveID] {
		return m.state.ActiveID
	}
	return m.startNext()
}

func (m *serviceLifecycleModel) responseAttempt(started, transportOK bool, status int) string {
	if !started || !transportOK {
		return "retry"
	}
	switch status {
	case 202, 409:
		m.pendingCommand = ""
		m.finish("cancelled")
		return "accepted"
	case 410:
		m.pendingCommand = ""
		m.outcome = "gone"
		m.startNext()
		return "gone"
	default:
		return "retry"
	}
}

func (m *serviceLifecycleModel) transportFailure() {
	switch m.operation {
	case "fetching", "polling":
		m.outcome = "failed"
		m.pendingCommand = ""
	case "posting":
		m.outcome = "retry"
	}
}

type panelMarkerFixture struct {
	ID        string
	Instance  string
	Heartbeat int64
}

func shouldOpenPanel(activeID string, marker any, now int64) bool {
	presence, ok := marker.(panelMarkerFixture)
	return !ok || presence.ID != activeID || !validRequestID(presence.Instance) || presence.Heartbeat < now-3
}

func TestServiceLifecycleQueuesEveryOccupiedPhaseFIFO(t *testing.T) {
	for _, test := range []struct {
		phase     string
		operation string
	}{
		{phase: "fetching", operation: "fetching"},
		{phase: "ready", operation: "idle"},
		{phase: "ready", operation: "posting"},
		{phase: "busy", operation: "polling"},
	} {
		t.Run(test.phase+"/"+test.operation, func(t *testing.T) {
			model := serviceLifecycleModel{state: serviceLifecycleFixture{
				Version: 1, ActiveID: requestIDA, Phase: test.phase,
			}, operation: test.operation}
			model.enqueue(requestIDB)
			model.enqueue(requestIDC)
			model.enqueue(requestIDB)
			if want := []string{requestIDB, requestIDC}; !reflect.DeepEqual(model.state.Queue, want) {
				t.Fatalf("queue = %#v, want FIFO %#v", model.state.Queue, want)
			}
		})
	}
}

func TestServiceLifecycleDeduplicatesActiveAndQueuedIDs(t *testing.T) {
	model := serviceLifecycleModel{state: serviceLifecycleFixture{
		ActiveID: requestIDA, Phase: "ready", Queue: []string{requestIDB},
	}}
	for _, id := range []string{requestIDA, requestIDB, "ABCDEF0123456789ABCDEF0123456789", "short", requestIDC} {
		model.enqueue(id)
	}
	if want := []string{requestIDB, requestIDC}; !reflect.DeepEqual(model.state.Queue, want) {
		t.Fatalf("deduplicated queue = %#v, want %#v", model.state.Queue, want)
	}
}

func TestServiceLifecycleAdvancesAfterTerminalAndStaleRequests(t *testing.T) {
	model := serviceLifecycleModel{state: serviceLifecycleFixture{
		ActiveID: requestIDA,
		Phase:    "busy",
		Queue:    []string{requestIDB, requestIDC},
	}, operation: "polling", staleIDs: map[string]bool{}}
	if got := model.finish("succeeded"); got != requestIDB {
		t.Fatalf("finish started %q, want queue head %q", got, requestIDB)
	}
	if model.outcome != "succeeded" || model.state.ActiveID != requestIDB || model.state.Phase != "fetching" || !reflect.DeepEqual(model.state.Queue, []string{requestIDC}) {
		t.Fatalf("advanced lifecycle = %#v", model)
	}

	model.state.Queue = []string{requestIDA}
	model.staleIDs[requestIDB] = true
	if got := model.restore(); got != requestIDA {
		t.Fatalf("stale restoration started %q, want %q", got, requestIDA)
	}
}

func TestServiceLifecycleRestoresFetchingReadyAndBusyRequests(t *testing.T) {
	for _, test := range []struct {
		phase     string
		operation string
	}{
		{phase: "fetching", operation: "fetching"},
		{phase: "ready", operation: "idle"},
		{phase: "ready", operation: "posting"},
		{phase: "busy", operation: "polling"},
	} {
		t.Run(test.phase+"/"+test.operation, func(t *testing.T) {
			model := serviceLifecycleModel{state: serviceLifecycleFixture{
				Version: 1, ActiveID: requestIDA, Phase: test.phase,
				Queue: []string{"short", requestIDB, requestIDA, requestIDB, requestIDC},
			}, operation: test.operation, staleIDs: map[string]bool{requestIDC: true}}
			if got := model.restore(); got != requestIDA || !reflect.DeepEqual(model.state.Queue, []string{requestIDB}) {
				t.Fatalf("valid restoration = (%q, %#v), want retained ownership and sanitized queue", got, model.state)
			}
		})
	}

	typeOfFixture := reflect.TypeOf(serviceLifecycleFixture{})
	for i := 0; i < typeOfFixture.NumField(); i++ {
		name := strings.ToLower(typeOfFixture.Field(i).Name)
		if strings.Contains(name, "password") || strings.Contains(name, "token") || strings.Contains(name, "url") || strings.Contains(name, "secret") {
			t.Errorf("persisted lifecycle contains secret field %q", name)
		}
	}

	for _, test := range []struct {
		name     string
		activeID string
		phase    string
	}{
		{name: "invalid version", activeID: requestIDA, phase: "ready"},
		{name: "invalid phase", activeID: requestIDA, phase: "failed"},
		{name: "missing active ID with phase", phase: "ready"},
		{name: "active ID without phase", activeID: requestIDA},
	} {
		t.Run(test.name, func(t *testing.T) {
			version := 1
			if test.name == "invalid version" {
				version = 2
			}
			model := serviceLifecycleModel{state: serviceLifecycleFixture{
				Version: version, ActiveID: test.activeID, Phase: test.phase, Queue: []string{requestIDB},
			}}
			if got := model.restore(); got != requestIDB || model.state.Version != 1 || model.state.ActiveID != requestIDB || model.state.Phase != "fetching" {
				t.Fatalf("invalid restoration = (%q, %#v), want queued request started", got, model.state)
			}
		})
	}
}

type startupRecoveryModel struct {
	phase                     string
	commandID, commandAction  string
	activeValid, sanitized    bool
	queue                     []string
	persisted, watched        int
	authPhase                 string
	commandCleared, authClear bool
	recovering                bool
}

func sameLifecycleQueueModel(left map[any]string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for key := range left {
		index, ok := key.(int)
		if !ok || index < 1 || index > len(right) {
			return false
		}
	}
	for index, id := range right {
		if left[index+1] != id {
			return false
		}
	}
	return true
}

func TestServiceLifecycleMalformedQueueIsNeverCanonical(t *testing.T) {
	for _, test := range []struct {
		name  string
		queue map[any]string
	}{
		{name: "secret string key", queue: map[any]string{1: requestIDB, "token": "secret"}},
		{name: "sparse key", queue: map[any]string{1: requestIDB, 3: requestIDC}},
		{name: "zero key", queue: map[any]string{0: requestIDC, 1: requestIDB}},
		{name: "negative key", queue: map[any]string{-1: requestIDC, 1: requestIDB}},
		{name: "fractional key", queue: map[any]string{1: requestIDB, 1.5: requestIDC}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if sameLifecycleQueueModel(test.queue, []string{requestIDB}) {
				t.Fatalf("malformed queue accepted as canonical: %#v", test.queue)
			}
		})
	}
}

func (m *startupRecoveryModel) begin() {
	m.recovering = true
	if m.sanitized {
		m.persisted++
	}
	if !m.activeValid {
		m.authClear = true
		m.commandCleared = m.commandID == requestIDA
		m.next()
	}
}

func (m *startupRecoveryModel) next() {
	if len(m.queue) == 0 {
		m.recovering = false
		m.watched++
		return
	}
	m.queue = m.queue[1:]
}

func (m *startupRecoveryModel) rehydrated() {
	if m.phase == "ready" && m.commandID == requestIDA && m.commandAction == "submit" {
		m.authPhase = "busy"
	} else {
		m.authPhase = m.phase
	}
	if m.phase == "busy" && m.commandID == requestIDA {
		m.commandCleared = true
	}
	m.recovering = false
	m.watched++
}

func (m *startupRecoveryModel) fetchFailed() {
	m.next()
}

func (m *startupRecoveryModel) retainedCommandDropsOwnership() {
	m.activeValid = false
	m.authPhase = ""
	m.commandID = ""
	m.commandAction = ""
	m.next()
	m.activeValid = true
	m.rehydrated()
}

func TestServiceLifecycleStartupPreservesUnchangedLifecycle(t *testing.T) {
	model := startupRecoveryModel{activeValid: true, phase: "ready"}
	model.begin()
	if model.persisted != 0 {
		t.Fatalf("valid unchanged lifecycle persisted %d times", model.persisted)
	}
}

func TestServiceLifecycleReadyCommandBecomesBusyBeforeAuthPublish(t *testing.T) {
	model := startupRecoveryModel{activeValid: true, phase: "ready", commandID: requestIDA, commandAction: "submit"}
	model.begin()
	model.rehydrated()
	if model.authPhase != "busy" {
		t.Fatalf("ready retained command published transient phase %q, want busy", model.authPhase)
	}
}

func TestServiceLifecycleBusyRecoveryClearsAcknowledgedCommandBeforePolling(t *testing.T) {
	model := startupRecoveryModel{activeValid: true, phase: "busy", commandID: requestIDA, commandAction: "submit"}
	model.begin()
	model.rehydrated()
	if !model.commandCleared || model.authPhase != "busy" {
		t.Fatalf("busy recovery = %#v, want stale command cleared before busy publish", model)
	}
}

func TestServiceLifecycleWatcherWaitsForRecoveryChain(t *testing.T) {
	model := startupRecoveryModel{queue: []string{requestIDB, requestIDC}}
	model.begin()
	model.fetchFailed()
	if model.watched != 0 || !model.recovering {
		t.Fatalf("failed active recovery registered watcher early: %#v", model)
	}
	model.rehydrated()
	if model.watched != 1 || model.recovering {
		t.Fatalf("settled queued recovery did not finalize once: %#v", model)
	}
}

func TestServiceLifecycleDroppedActiveScrubsMatchingSharedState(t *testing.T) {
	model := startupRecoveryModel{commandID: requestIDA, commandAction: "submit"}
	model.begin()
	if !model.authClear || !model.commandCleared {
		t.Fatalf("dropped active retained stale shared state: %#v", model)
	}
}

func TestServiceLifecycleRetainedCommandOwnershipDropCompletesRecovery(t *testing.T) {
	model := startupRecoveryModel{
		activeValid: true, phase: "ready", commandID: requestIDA, commandAction: "submit",
		queue: []string{requestIDB}, recovering: true,
	}
	model.retainedCommandDropsOwnership()
	if model.authPhase != "ready" || len(model.queue) != 0 || model.recovering || model.watched != 1 {
		t.Fatalf("retained command ownership drop left recovery incomplete: %#v", model)
	}
}

func TestServiceCancellationRetriesStartAndTransportFailures(t *testing.T) {
	for _, test := range []struct {
		started, transportOK bool
		status               int
	}{
		{started: false, transportOK: true, status: 202},
		{started: true, transportOK: false, status: 202},
		{started: true, transportOK: true, status: 200},
		{started: true, transportOK: true, status: 500},
	} {
		model := serviceLifecycleModel{pendingCommand: "cancel"}
		if got := model.responseAttempt(test.started, test.transportOK, test.status); got != "retry" {
			t.Errorf("responseAttempt(%v, %v, %d) = %q, want retry", test.started, test.transportOK, test.status, got)
		}
		if model.pendingCommand != "cancel" {
			t.Errorf("responseAttempt(%v, %v, %d) cleared pending cancellation", test.started, test.transportOK, test.status)
		}
	}
}

func TestServiceCancellationTreatsConflictAsAcknowledged(t *testing.T) {
	for _, status := range []int{202, 409} {
		model := serviceLifecycleModel{
			state: serviceLifecycleFixture{
				Version: 1, ActiveID: requestIDA, Phase: "ready", Queue: []string{requestIDB, requestIDC},
			},
			pendingCommand: "cancel",
		}
		if got := model.responseAttempt(true, true, status); got != "accepted" {
			t.Fatalf("status %d outcome = %q, want accepted", status, got)
		}
		if model.pendingCommand != "" || model.outcome != "cancelled" || model.state.ActiveID != requestIDB || model.state.Phase != "fetching" || !reflect.DeepEqual(model.state.Queue, []string{requestIDC}) {
			t.Fatalf("status %d cancellation state = %#v, want terminal finish and FIFO advance", status, model)
		}
	}
}

func TestServiceCancellationTreatsGoneAsTerminal(t *testing.T) {
	model := serviceLifecycleModel{
		state:          serviceLifecycleFixture{ActiveID: requestIDA, Phase: "ready", Queue: []string{requestIDB}},
		pendingCommand: "cancel",
	}
	if got := model.responseAttempt(true, true, 410); got != "gone" {
		t.Fatalf("gone outcome = %q, want gone", got)
	}
	if model.pendingCommand != "" || model.outcome != "gone" || model.state.ActiveID != requestIDB || model.state.Phase != "fetching" {
		t.Fatalf("gone cancellation state = %#v, want ownership advanced", model)
	}
}

func TestServiceCancellationDoesNotTurnIntoGenericBridgeFailure(t *testing.T) {
	wantState := serviceLifecycleFixture{Version: 1, ActiveID: requestIDA, Phase: "ready", Queue: []string{requestIDB}}
	model := serviceLifecycleModel{state: wantState, outcome: "cancelling", pendingCommand: "cancel"}
	if got := model.responseAttempt(true, false, 0); got != "retry" || model.outcome != "cancelling" || model.pendingCommand != "cancel" || !reflect.DeepEqual(model.state, wantState) {
		t.Fatalf("cancellation transport failure = (%q, %#v), want exact retained cancellation", got, model)
	}
}

func TestServiceOrdinaryTransportFailuresRemainFailures(t *testing.T) {
	for _, test := range []struct {
		name        string
		operation   string
		command     string
		wantOutcome string
		wantCommand bool
	}{
		{name: "fetch", operation: "fetching", wantOutcome: "failed"},
		{name: "result", operation: "polling", wantOutcome: "failed"},
		{name: "submit", operation: "posting", command: "submit", wantOutcome: "retry", wantCommand: true},
		{name: "confirm", operation: "posting", command: "confirm", wantOutcome: "retry", wantCommand: true},
	} {
		model := serviceLifecycleModel{operation: test.operation, pendingCommand: test.command}
		model.transportFailure()
		commandRetained := model.pendingCommand != ""
		if model.outcome != test.wantOutcome || commandRetained != test.wantCommand {
			t.Fatalf("ordinary %s transport failure = (%q, command retained %v), want (%q, %v)", test.name, model.outcome, commandRetained, test.wantOutcome, test.wantCommand)
		}
	}
}

func TestPanelPresenceMatchesOnlyCurrentRequest(t *testing.T) {
	now := int64(10_000)
	for _, test := range []struct {
		name   string
		marker any
		open   bool
	}{
		{name: "false", marker: false, open: true},
		{name: "malformed", marker: map[string]any{"id": requestIDA}, open: true},
		{name: "mismatched", marker: panelMarkerFixture{ID: requestIDB, Instance: requestIDC, Heartbeat: now}, open: true},
		{name: "stale", marker: panelMarkerFixture{ID: requestIDA, Instance: requestIDC, Heartbeat: now - 4}, open: true},
		{name: "matching fresh", marker: panelMarkerFixture{ID: requestIDA, Instance: requestIDC, Heartbeat: now - 3}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := shouldOpenPanel(requestIDA, test.marker, now); got != test.open {
				t.Fatalf("shouldOpenPanel = %v, want %v", got, test.open)
			}
		})
	}
}

func TestPanelReloadLeavesOldMarkerUntilHydration(t *testing.T) {
	now := int64(20_000)
	marker := any(panelMarkerFixture{ID: requestIDA, Instance: requestIDB, Heartbeat: now - 4})
	if !shouldOpenPanel(requestIDA, marker, now) {
		t.Fatal("stale marker from old panel VM prevented reopening")
	}
	marker = panelMarkerFixture{ID: requestIDA, Instance: requestIDC, Heartbeat: now}
	if shouldOpenPanel(requestIDA, marker, now) {
		t.Fatal("hydrated replacement marker requested a duplicate panel")
	}
}

type panelPresenceModel struct {
	open                bool
	commands            int
	requestID, instance string
	authID, phase       string
	marker              any
}

func (m *panelPresenceModel) onOpen(sharedAuthID, sharedPhase string, now int64) {
	m.open = true
	m.authID = sharedAuthID
	m.phase = sharedPhase
	m.requestID = sharedAuthID
	m.marker = panelMarkerFixture{ID: sharedAuthID, Instance: m.instance, Heartbeat: now}
}

func (m *panelPresenceModel) close(capturedID, capturedInstance string) {
	m.open = false
	m.requestID = ""
	marker, ok := m.marker.(panelMarkerFixture)
	if ok && marker.ID == capturedID && marker.Instance == capturedInstance {
		m.marker = false
	}
}

func TestPanelCloseClearsExactOwnedMarkerWithoutCancellation(t *testing.T) {
	model := panelPresenceModel{open: true, requestID: requestIDA, instance: requestIDB,
		marker: panelMarkerFixture{ID: requestIDA, Instance: requestIDB, Heartbeat: 10}}
	model.close(requestIDA, requestIDB)
	if model.marker != false || model.commands != 0 || model.open || model.requestID != "" {
		t.Fatalf("owned close lifecycle = %#v", model)
	}
}

func TestPanelOldCloseCallbackCannotClearReplacementMarker(t *testing.T) {
	want := panelMarkerFixture{ID: requestIDA, Instance: requestIDC, Heartbeat: 11}
	model := panelPresenceModel{open: true, requestID: requestIDA, instance: requestIDC, marker: want}
	model.close(requestIDA, requestIDB)
	if !reflect.DeepEqual(model.marker, want) || model.commands != 0 {
		t.Fatalf("old close callback changed replacement ownership: %#v", model)
	}
}

func TestPanelOnOpenHydratesSharedAuthAndPublishesPresence(t *testing.T) {
	model := panelPresenceModel{instance: requestIDB}
	model.onOpen(requestIDA, "busy", 25)
	wantMarker := panelMarkerFixture{ID: requestIDA, Instance: requestIDB, Heartbeat: 25}
	if !model.open || model.authID != requestIDA || model.phase != "busy" || model.requestID != requestIDA || !reflect.DeepEqual(model.marker, wantMarker) {
		t.Fatalf("onOpen hydration = %#v", model)
	}
}

func TestPanelReadyCloseClearsMarkerWithoutCancellation(t *testing.T) {
	model := panelPresenceModel{open: true, requestID: requestIDA, instance: requestIDB, authID: requestIDA, phase: "ready",
		marker: panelMarkerFixture{ID: requestIDA, Instance: requestIDB, Heartbeat: 30}}
	model.close(requestIDA, requestIDB)
	if model.marker != false || model.commands != 0 {
		t.Fatalf("ready close lifecycle = %#v", model)
	}
}

func TestPanelBusyCloseClearsMarkerWithoutCancellation(t *testing.T) {
	model := panelPresenceModel{open: true, requestID: requestIDA, instance: requestIDB, authID: requestIDA, phase: "busy",
		marker: panelMarkerFixture{ID: requestIDA, Instance: requestIDB, Heartbeat: 30}}
	model.close(requestIDA, requestIDB)
	if model.marker != false || model.commands != 0 {
		t.Fatalf("busy close lifecycle = %#v", model)
	}
}

func TestPanelProgrammaticTerminalCloseDoesNotDuplicateCommand(t *testing.T) {
	for _, phase := range []string{"success", "cancelled"} {
		t.Run(phase, func(t *testing.T) {
			model := panelPresenceModel{open: true, commands: 1, requestID: requestIDA, instance: requestIDB, phase: phase,
				marker: panelMarkerFixture{ID: requestIDA, Instance: requestIDB, Heartbeat: 30}}
			model.close(requestIDA, requestIDB)
			if model.commands != 1 || model.marker != false {
				t.Fatalf("programmatic %s close = %#v", phase, model)
			}
		})
	}
}

type servicePanelOpeningModel struct {
	activeID   string
	marker     any
	openingFor string
	openingAt  int64
	toggles    int
}

func (m *servicePanelOpeningModel) requestOpen(now int64) {
	if !shouldOpenPanel(m.activeID, m.marker, now) {
		m.openingFor = ""
		m.openingAt = 0
		return
	}
	if m.openingFor == m.activeID && now-m.openingAt < 1 {
		return
	}
	m.openingFor = m.activeID
	m.openingAt = now
	m.toggles++
}

func TestServiceModelBusyCloseReopensAtMostOncePerSecond(t *testing.T) {
	model := servicePanelOpeningModel{activeID: requestIDA, marker: false}
	model.requestOpen(10)
	model.requestOpen(10)
	if model.toggles != 1 {
		t.Fatalf("same-second closed-panel toggles = %d, want 1", model.toggles)
	}
	model.requestOpen(11)
	if model.toggles != 2 {
		t.Fatalf("nonterminal closed panel was not retried: %#v", model)
	}
}

func TestServiceModelFreshMarkerPreventsVisiblePanelToggleClosed(t *testing.T) {
	model := servicePanelOpeningModel{activeID: requestIDA, openingFor: requestIDA, openingAt: 10,
		marker: panelMarkerFixture{ID: requestIDA, Instance: requestIDB, Heartbeat: 11}}
	model.requestOpen(11)
	model.requestOpen(12)
	if model.toggles != 0 || model.openingFor != "" {
		t.Fatalf("fresh visible panel toggled or retained guard: %#v", model)
	}
}

func TestServiceReloadPreservesLiveMatchingMarker(t *testing.T) {
	marker := panelMarkerFixture{ID: requestIDA, Instance: requestIDB, Heartbeat: 40}
	model := servicePanelOpeningModel{activeID: requestIDA, marker: marker}
	model.requestOpen(40)
	if model.toggles != 0 || !reflect.DeepEqual(model.marker, marker) {
		t.Fatalf("service reload changed live marker: %#v", model)
	}
}

func TestServiceRetryOpensExactlyOnce(t *testing.T) {
	model := servicePanelOpeningModel{activeID: requestIDA, marker: false}
	model.requestOpen(50)
	model.requestOpen(50)
	if model.toggles != 1 {
		t.Fatalf("retry toggles = %d, want exactly 1", model.toggles)
	}
}

type serviceModel struct {
	generation                 int
	active, pending            bool
	fetching, posting, polling bool
	auth, command              bool
	phase                      string
	panelOpen, requestOpen     bool
	confirmOnly, exitCancel    bool
	commandID, commandAction   string
	commandIdentity            int
	privateSecrets             bool
}

func (m *serviceModel) exit() {
	m.generation++
	m.active = false
	m.pending = false
	m.fetching = false
	m.posting = false
	m.polling = false
	m.privateSecrets = false
}

func (m *serviceModel) acknowledge(id, action string, identity int) {
	if m.command && m.commandID == id && m.commandAction == action && m.commandIdentity == identity {
		m.command = false
		m.commandID = ""
		m.commandAction = ""
	}
}

func TestServiceModelExitRetainsSharedCommandWithoutCancellation(t *testing.T) {
	for _, posting := range []bool{false, true} {
		model := serviceModel{
			generation: 7, active: true, posting: posting, auth: true, command: true,
			phase: "ready", commandID: requestIDA, commandAction: "submit", commandIdentity: 4,
			privateSecrets: true,
		}
		model.exit()
		if !model.command || model.commandID != requestIDA || model.commandAction != "submit" || model.commandIdentity != 4 {
			t.Fatalf("exit posting=%v changed retained command: %#v", posting, model)
		}
		if model.privateSecrets || model.active || model.posting || model.generation != 8 || model.exitCancel {
			t.Fatalf("exit posting=%v private lifecycle = %#v", posting, model)
		}
	}
}

func TestServiceModelAcknowledgmentDoesNotClearReplacementCommand(t *testing.T) {
	model := serviceModel{command: true, commandID: requestIDA, commandAction: "submit", commandIdentity: 12}
	model.acknowledge(requestIDA, "submit", 11)
	if !model.command || model.commandIdentity != 12 {
		t.Fatalf("old acknowledgment cleared replacement command: %#v", model)
	}
	model.acknowledge(requestIDA, "submit", 12)
	if model.command {
		t.Fatalf("matching acknowledgment retained command: %#v", model)
	}
}

func (m *serviceModel) commandFor(generation int, action string) {
	if generation != m.generation || !m.active || m.phase != "ready" || m.posting {
		return
	}
	if (action == "submit" && m.confirmOnly) || (action == "confirm" && !m.confirmOnly) {
		return
	}
	m.posting = true
	if action == "submit" {
		m.phase = "busy"
	}
	m.auth = true
}

func (m *serviceModel) callback(generation int, idCurrent bool) {
	if generation != m.generation || !idCurrent {
		return
	}
	m.posting = false
}

func (m *serviceModel) retry(generation int, idCurrent bool) {
	if generation != m.generation || !idCurrent {
		return
	}
	m.posting = false
	m.polling = false
	m.phase = "ready"
	m.auth = true
	m.requestOpen = !m.panelOpen
}

func (m *serviceModel) panelClosed() {
	if m.phase == "busy" {
		m.panelOpen = false
	}
}

func (m *serviceModel) failPending() {
	if !m.pending {
		return
	}
	m.auth = true
	m.phase = "failed"
	m.requestOpen = !m.panelOpen
	m.generation++
	m.pending = false
	m.fetching = false
}

func TestServiceModelDuplicateCommandDoesNotMutateState(t *testing.T) {
	want := serviceModel{generation: 3, active: true, posting: true, auth: true, phase: "busy"}
	got := want
	got.commandFor(3, "submit")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("duplicate command changed state: got %#v, want %#v", got, want)
	}
}

func TestServiceModelRejectsIncompatibleCommands(t *testing.T) {
	tests := []struct {
		name        string
		confirmOnly bool
		action      string
	}{
		{name: "submit for confirmation", confirmOnly: true, action: "submit"},
		{name: "confirm for password", action: "confirm"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want := serviceModel{generation: 1, active: true, auth: true, phase: "ready", confirmOnly: test.confirmOnly}
			got := want
			got.commandFor(1, test.action)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("incompatible command changed state: got %#v, want %#v", got, want)
			}
		})
	}
}

func TestServiceModelAcceptsCancelForBothRequestKinds(t *testing.T) {
	for _, confirmOnly := range []bool{false, true} {
		got := serviceModel{generation: 1, active: true, auth: true, phase: "ready", confirmOnly: confirmOnly}
		got.commandFor(1, "cancel")
		if !got.posting || got.phase != "ready" {
			t.Fatalf("cancel compatibility for confirmOnly=%v: %#v", confirmOnly, got)
		}
	}
}

func TestServiceModelMalformedCallbackAndHTTPRefusalFail(t *testing.T) {
	for _, name := range []string{"malformed callback", "synchronous refusal"} {
		t.Run(name, func(t *testing.T) {
			got := serviceModel{generation: 2, active: true, posting: true, auth: true, phase: "busy"}
			got.generation++
			got.active = false
			got.posting = false
			got.phase = "failed"
			if got.generation != 3 || got.active || got.posting || !got.auth || got.phase != "failed" {
				t.Fatalf("failure state = %#v", got)
			}
		})
	}
}

func TestServiceModelStaleCallbackDoesNotMutateState(t *testing.T) {
	want := serviceModel{generation: 4, active: true, posting: true, polling: true, auth: true, phase: "busy"}
	for _, callback := range []func(*serviceModel){
		func(m *serviceModel) { m.callback(3, true) },
		func(m *serviceModel) { m.callback(4, false) },
	} {
		got := want
		callback(&got)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("stale callback changed state: got %#v, want %#v", got, want)
		}
	}
}

func TestServiceModelRetryTransitionsBusyToReady(t *testing.T) {
	got := serviceModel{generation: 5, active: true, posting: true, polling: true, auth: true, phase: "busy"}
	got.retry(5, true)
	want := serviceModel{generation: 5, active: true, auth: true, phase: "ready", requestOpen: true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("retry state = %#v, want %#v", got, want)
	}
}

func TestServiceModelBusyCloseAndRetryReopen(t *testing.T) {
	got := serviceModel{generation: 2, active: true, polling: true, auth: true, phase: "busy", panelOpen: true}
	got.panelClosed()
	if got.panelOpen {
		t.Fatal("busy close did not record panel_open false")
	}
	got.retry(2, true)
	if !got.requestOpen {
		t.Fatal("retry after busy close did not request panel reopen")
	}
}

func TestServiceModelPreActiveFailurePublishesAndOpensPanel(t *testing.T) {
	got := serviceModel{generation: 6, pending: true, fetching: true}
	got.failPending()
	want := serviceModel{generation: 7, auth: true, phase: "failed", requestOpen: true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pre-active failure state = %#v, want %#v", got, want)
	}
	got.callback(6, true)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("late pre-active callback changed terminal state: got %#v, want %#v", got, want)
	}
}

func TestServiceModelContainsNoSecretsOrLocations(t *testing.T) {
	typeOfModel := reflect.TypeOf(serviceModel{})
	for i := 0; i < typeOfModel.NumField(); i++ {
		name := strings.ToLower(typeOfModel.Field(i).Name)
		if strings.Contains(name, "password") || strings.Contains(name, "token") || strings.Contains(name, "url") {
			t.Errorf("model contains durable secret or location field %q", name)
		}
	}
}

func parsePluginManifest(source string) (pluginManifest, error) {
	manifest := pluginManifest{root: make(map[string]any)}
	current := manifest.root
	section := "root"
	allowed := map[string]map[string]bool{
		"root":    keySet("id", "name", "version", "plugin_api", "author", "license", "icon", "description", "tags", "dependencies"),
		"service": keySet("id", "entry"),
		"panel":   keySet("id", "entry", "width", "height", "placement", "position", "open_near_click", "dismiss_on_outside_click"),
		"setting": keySet("key", "type", "label_key", "description_key", "default"),
	}
	for lineNumber, rawLine := range strings.Split(source, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[[") {
			if line != "[[service]]" && line != "[[panel]]" && line != "[[setting]]" {
				return manifest, fmt.Errorf("line %d: invalid table header %q", lineNumber+1, line)
			}
			section = strings.TrimSuffix(strings.TrimPrefix(line, "[["), "]]")
			current = make(map[string]any)
			switch section {
			case "service":
				manifest.services = append(manifest.services, current)
			case "panel":
				manifest.panels = append(manifest.panels, current)
			case "setting":
				manifest.settings = append(manifest.settings, current)
			}
			continue
		}
		key, rawValue, found := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		rawValue = strings.TrimSpace(rawValue)
		if !found || key == "" || rawValue == "" {
			return manifest, fmt.Errorf("line %d: malformed assignment", lineNumber+1)
		}
		if !allowed[section][key] {
			return manifest, fmt.Errorf("line %d: unknown %s key %q", lineNumber+1, section, key)
		}
		if _, duplicate := current[key]; duplicate {
			return manifest, fmt.Errorf("line %d: duplicate %s key %q", lineNumber+1, section, key)
		}
		value, err := parseManifestValue(rawValue)
		if err != nil {
			return manifest, fmt.Errorf("line %d: %w", lineNumber+1, err)
		}
		current[key] = value
	}
	return manifest, nil
}

func parseManifestValue(raw string) (any, error) {
	if strings.HasPrefix(raw, `"`) {
		return parseManifestString(raw)
	}
	if raw == "true" || raw == "false" {
		return raw == "true", nil
	}
	if strings.HasPrefix(raw, "[") {
		if !strings.HasSuffix(raw, "]") {
			return nil, fmt.Errorf("invalid string array %q", raw)
		}
		inner := strings.TrimSpace(raw[1 : len(raw)-1])
		if inner == "" {
			return []string{}, nil
		}
		parts := strings.Split(inner, ",")
		values := make([]string, 0, len(parts))
		for _, part := range parts {
			value, err := parseManifestString(strings.TrimSpace(part))
			if err != nil {
				return nil, fmt.Errorf("invalid string array %q", raw)
			}
			values = append(values, value)
		}
		return values, nil
	}
	if raw == "" || (raw != "0" && (raw[0] < '1' || raw[0] > '9')) {
		return nil, fmt.Errorf("invalid value %q", raw)
	}
	for _, digit := range raw[1:] {
		if digit < '0' || digit > '9' {
			return nil, fmt.Errorf("invalid value %q", raw)
		}
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid value %q", raw)
	}
	return value, nil
}

func parseManifestString(raw string) (string, error) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' || strings.Contains(raw, `\`) {
		return "", fmt.Errorf("invalid quoted string %q", raw)
	}
	for _, character := range raw[1 : len(raw)-1] {
		if character < ' ' || character == 0x7f {
			return "", fmt.Errorf("invalid quoted string %q", raw)
		}
	}
	value, err := strconv.Unquote(raw)
	if err != nil {
		return "", fmt.Errorf("invalid quoted string: %w", err)
	}
	return value, nil
}

func TestParseManifestValueQuotedStrings(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    any
		wantErr bool
	}{
		{name: "scalar", raw: `"Bitwarden Keyring"`, want: "Bitwarden Keyring"},
		{name: "array", raw: `["bitwarden", "password", "security"]`, want: []string{"bitwarden", "password", "security"}},
		{name: "scalar Go hex escape", raw: `"Bitwarden\x20Keyring"`, wantErr: true},
		{name: "scalar Go octal escape", raw: `"Bitwarden\040Keyring"`, wantErr: true},
		{name: "array Go hex escape", raw: `["bitwarden", "pass\x77ord"]`, wantErr: true},
		{name: "array Go octal escape", raw: `["bitwarden", "pass\167ord"]`, wantErr: true},
		{name: "array unquoted element", raw: `["bitwarden", password]`, wantErr: true},
		{name: "scalar control character", raw: "\"Bitwarden\nKeyring\"", wantErr: true},
		{name: "array control character", raw: "[\"bitwarden\", \"pass\nword\"]", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseManifestValue(test.raw)
			if test.wantErr {
				if err == nil {
					t.Fatalf("parseManifestValue(%q) = %#v, want error", test.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseManifestValue(%q) error = %v", test.raw, err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("parseManifestValue(%q) = %#v, want %#v", test.raw, got, test.want)
			}
		})
	}
}

func TestParseManifestValueIntegers(t *testing.T) {
	tests := []struct {
		raw     string
		want    int
		wantErr bool
	}{
		{raw: "0", want: 0},
		{raw: "8", want: 8},
		{raw: "400", want: 400},
		{raw: "300", want: 300},
		{raw: "08", wantErr: true},
		{raw: "0400", wantErr: true},
		{raw: "+8", wantErr: true},
		{raw: "-1", wantErr: true},
		{raw: " 8", wantErr: true},
		{raw: "8 ", wantErr: true},
		{raw: "1_0", wantErr: true},
		{raw: "0x8", wantErr: true},
		{raw: "8.0", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			got, err := parseManifestValue(test.raw)
			if test.wantErr {
				if err == nil {
					t.Fatalf("parseManifestValue(%q) = %#v, want error", test.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseManifestValue(%q) error = %v", test.raw, err)
			}
			if got != test.want {
				t.Errorf("parseManifestValue(%q) = %#v, want %d", test.raw, got, test.want)
			}
		})
	}
}

func assertPluginManifest(t *testing.T, got pluginManifest) {
	t.Helper()
	wantRoot := map[string]any{
		"id": "frap129/noctalia-bitwarden-keyring", "name": "Bitwarden Keyring", "version": "0.5.0", "plugin_api": 16,
		"author": "frap129", "license": "MIT", "icon": "brand-bitwarden",
		"description": "Secure prompts for the Bitwarden-backed Secret Service and SSH agent.",
		"tags":        []string{"bitwarden", "password", "security"}, "dependencies": []string{"bitwarden-keyring"},
	}
	wantServices := []map[string]any{{"id": "service", "entry": "service.luau"}}
	wantPanels := []map[string]any{{
		"id": "unlock", "entry": "panel.luau", "width": 400, "height": 300, "placement": "floating", "position": "center",
		"open_near_click": false, "dismiss_on_outside_click": false,
	}}
	wantSettings := []map[string]any{
		{"key": "show_bitwarden_icon", "type": "bool", "label_key": "settings.show_bitwarden_icon.label", "description_key": "settings.show_bitwarden_icon.description", "default": true},
		{"key": "auto_close_on_success", "type": "bool", "label_key": "settings.auto_close_on_success.label", "description_key": "settings.auto_close_on_success.description", "default": true},
		{"key": "auto_close_on_cancel", "type": "bool", "label_key": "settings.auto_close_on_cancel.label", "description_key": "settings.auto_close_on_cancel.description", "default": true},
	}
	if !reflect.DeepEqual(got.root, wantRoot) {
		t.Errorf("plugin.toml root = %#v, want %#v", got.root, wantRoot)
	}
	if !reflect.DeepEqual(got.services, wantServices) {
		t.Errorf("plugin.toml services = %#v, want %#v", got.services, wantServices)
	}
	if !reflect.DeepEqual(got.panels, wantPanels) {
		t.Errorf("plugin.toml panels = %#v, want %#v", got.panels, wantPanels)
	}
	if !reflect.DeepEqual(got.settings, wantSettings) {
		t.Errorf("plugin.toml settings = %#v, want %#v", got.settings, wantSettings)
	}
}

func assertTranslations(t *testing.T, contents []byte) {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Errorf("parse translations/en.json: %v", err)
		return
	}
	requireExactKeys(t, "translations", document, keySet("settings", "panel"))
	settings := requireTranslationObject(t, document, "settings")
	settingNames := keySet("show_bitwarden_icon", "auto_close_on_success", "auto_close_on_cancel")
	requireExactKeys(t, "translations.settings", settings, settingNames)
	for name := range settingNames {
		setting := requireTranslationObject(t, settings, name)
		requireExactKeys(t, "translations.settings."+name, setting, keySet("label", "description"))
		requireNonemptyTranslationStrings(t, "translations.settings."+name, setting)
	}
	panel := requireTranslationObject(t, document, "panel")
	panelKeys := keySet("title", "password_placeholder", "unlock", "confirm", "unlocking", "cancel", "success", "cancelled", "invalid_request", "bridge_unreachable", "incorrect_password", "unlock_failed")
	requireExactKeys(t, "translations.panel", panel, panelKeys)
	requireNonemptyTranslationStrings(t, "translations.panel", panel)
	if got, _ := panel["title"].(string); got != "Bitwarden Keyring" {
		t.Errorf("translation panel.title = %q, want %q", got, "Bitwarden Keyring")
	}
	if got, _ := panel["password_placeholder"].(string); got != "Master Password" {
		t.Errorf("translation panel.password_placeholder = %q, want %q", got, "Master Password")
	}
}

func requireTranslationObject(t *testing.T, parent map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := parent[key].(map[string]any)
	if !ok {
		t.Errorf("translation %s must be an object", key)
		return map[string]any{}
	}
	return value
}

func requireExactKeys(t *testing.T, path string, object map[string]any, expected map[string]bool) {
	t.Helper()
	for key := range object {
		if !expected[key] {
			t.Errorf("%s has unknown key %q", path, key)
		}
	}
	for key := range expected {
		if _, ok := object[key]; !ok {
			t.Errorf("%s is missing key %q", path, key)
		}
	}
}

func requireNonemptyTranslationStrings(t *testing.T, path string, object map[string]any) {
	t.Helper()
	for key, value := range object {
		text, ok := value.(string)
		if !ok || strings.TrimSpace(text) == "" {
			t.Errorf("%s.%s must be a nonempty string", path, key)
		}
	}
}

func keySet(keys ...string) map[string]bool {
	set := make(map[string]bool, len(keys))
	for _, key := range keys {
		set[key] = true
	}
	return set
}
