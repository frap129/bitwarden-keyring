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
		`--!nonstrict`, `local auth`, `local password`, `local inputKey`, `local inputAccepting`, `local suppressCloseCancel`,
		`function render()`, `ui.column`, `assets/bitwarden.svg`, `noctalia.getConfig("show_bitwarden_icon")`,
		`key = "password-" .. inputKey`, `value = ""`, `password = true`, `focus = true`, `enabled = auth.phase == "ready"`,
		`local capturedInputKey = inputKey`, `local capturedId = auth.id`, `onChange = function(value)`, `onSubmit = function()`,
		`handlePasswordChange(value, capturedInputKey, capturedId)`, `handleUnlock(capturedInputKey, capturedId)`, `panel.render(render())`,
		`function onOpen()`, `function onClose()`, `panel.close()`, `noctalia.state.set("panel_open", true)`, `noctalia.state.set("panel_open", false)`,
		`value.id`, `value.title`, `value.prompt`, `value.confirm_only`, `value.phase`, `value.error`,
		`action = "submit"`, `action = "cancel"`, `action = "confirm"`,
		`submitted = nil`, `password = ""`, `inputKey = inputKey + 1`,
		`noctalia.getConfig("auto_close_on_cancel")`, `noctalia.getConfig("auto_close_on_success")`,
		`noctalia.state.watch("auth", onAuthChanged)`,
		`if capturedInputKey ~= inputKey or auth == nil or capturedId ~= auth.id then return end`,
		`if not inputAccepting or auth.phase ~= "ready" or auth.confirm_only then return end`,
		`if auth == nil or auth.phase ~= "failed" then return end`,
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
		"frameTick", "onFrame", "setUpdateInterval", "setTimeout", "setInterval", "animation", "timer", "geometry",
		"pluginSettings", "openPanel", "closePanel", "saveSettings",
		"pluginApi", "SocketServer", "Quickshell", "runAsync", "runStream", "print(",
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
	if !regexp.MustCompile(`(?s)function onDismiss\(\)\s+if auth == nil or auth\.phase ~= "failed" then return end\s+clearPassword\(\)\s+requestProgrammaticDismiss\(\)`).MatchString(source) {
		t.Error("panel.luau dismiss must validate the current failed auth before suppressing close")
	}
	if !regexp.MustCompile(`(?s)function onInvalidDismiss\(\)\s+if auth ~= nil then return end\s+clearPassword\(\)\s+requestProgrammaticDismiss\(\)`).MatchString(source) {
		t.Error("panel.luau invalid-state dismiss must not close or suppress a valid request")
	}
	if !strings.Contains(source, `onClick = "onInvalidDismiss"`) {
		t.Error("panel.luau invalid state is not dismissible")
	}
	if !regexp.MustCompile(`(?s)function onClose\(\).*?if not suppressCloseCancel and auth ~= nil and auth\.phase == "ready" then\s+auth\.phase = "cancelling"\s+clearPassword\(\)\s+noctalia\.state\.set\("command", \{ action = "cancel", id = auth\.id \}\)`).MatchString(source) {
		t.Error("panel.luau close must transition ready auth before publishing one cancellation")
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
	if !m.suppressed && m.authComplete && m.phase == "ready" {
		m.phase = "cancelling"
		m.password = ""
		m.inputKey++
		m.commands++
	}
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

func TestPanelModelRepeatedCloseCancelsOnce(t *testing.T) {
	model := panelCallbackModel{authComplete: true, inputKey: 2, phase: "ready", password: "secret"}
	model.close()
	model.close()
	if model.commands != 1 || model.phase != "cancelling" || model.password != "" || model.inputKey != 3 {
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
		`Authorization = "Bearer "`, `/v1/request`, `/v1/response`, `/v1/result`,
		`noctalia.setUpdateInterval(250)`, `function update()`, `capturedGeneration ~= generation`,
		`capturedId ~= pendingId`, `capturedId ~= active.id`, `status ~= 200 and status ~= 204 and status ~= 409`,
		`noctalia.state.set("command", nil)`, `noctalia.state.set("auth", false)`, `noctalia.state.get("panel_open")`,
		`id = id`, `title = title`, `prompt = prompt`, `confirm_only = confirmOnly`, `phase = phase`, `error = errorText`,
		`value.password = nil`, `wire.password = nil`, `body = nil`,
		`value.retry == nil or type(value.retry) == "boolean"`, `local terminal = {`,
		`noctalia.state.set("auth", terminal)`, `local showPanel = owner == nil and validId(pendingId)`,
		`if action == "submit" and active.confirmOnly == true then password = nil return end`,
		`if active ~= nil and active.phase == "ready" and bridgeToken ~= nil and bridgeBaseUrl ~= nil then`,
		`result = "cancelled"`, `function ignoreExitResponse`, `noctalia.http({`, `pcall(noctalia.http, request, ignoreExitResponse)`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("service.luau does not contain required literal %q", required)
		}
	}
	if strings.Count(source, `capturedGeneration ~= generation`) < 3 {
		t.Error("service.luau must generation-guard every HTTP callback")
	}
	if strings.Count(source, `capturedId ~=`) < 3 {
		t.Error("service.luau must ID-guard every HTTP callback")
	}
	publishTerminal := strings.Index(source, `noctalia.state.set("auth", terminal)`)
	invalidateTerminal := strings.Index(source, "generation = generation + 1")
	if publishTerminal < 0 || invalidateTerminal < 0 || publishTerminal > invalidateTerminal {
		t.Error("service.luau must publish terminal auth before invalidating callbacks")
	}
	for _, forbidden := range []string{
		`panel_open", nil`, `panel_open", false`, `panel_open", true`,
		"os.execute", "io.popen", "noctalia.exec", "noctalia.spawn", "console.log", "logger", "notify(", "noctalia.http.request",
		`publish(active.id, active.title, active.prompt, active.confirmOnly, "cancelling"`, `result.error`,
		`function(res)
    body`, `function(res)
    token`, `function(res)
    baseUrl`, `activeRequest`,
	} {
		if strings.Contains(source, forbidden) {
			t.Errorf("service.luau contains forbidden literal %q", forbidden)
		}
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

type serviceModel struct {
	generation                 int
	active, pending            bool
	fetching, posting, polling bool
	auth, command              bool
	phase                      string
	panelOpen, requestOpen     bool
	confirmOnly, exitCancel    bool
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

func (m *serviceModel) restart() {
	m.exitCancel = m.active && m.phase == "ready"
	m.generation++
	m.active = false
	m.pending = false
	m.fetching = false
	m.posting = false
	m.polling = false
	m.auth = false
	m.command = false
	m.phase = ""
	m.requestOpen = false
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

func TestServiceModelExitCancelsOnlyReadyRequest(t *testing.T) {
	for _, test := range []struct {
		phase      string
		wantCancel bool
	}{{phase: "ready", wantCancel: true}, {phase: "busy"}} {
		got := serviceModel{generation: 4, active: true, auth: true, command: true, phase: test.phase}
		got.restart()
		if got.exitCancel != test.wantCancel {
			t.Fatalf("exit cancellation for %s = %v, want %v", test.phase, got.exitCancel, test.wantCancel)
		}
		if got.active || got.auth || got.command || got.generation != 5 {
			t.Fatalf("exit did not clear lifecycle for %s: %#v", test.phase, got)
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

func TestServiceModelRestartPreservesPanelAndInvalidatesCallbacks(t *testing.T) {
	got := serviceModel{generation: 8, active: true, pending: true, fetching: true, posting: true, polling: true, auth: true, command: true, phase: "busy", panelOpen: true}
	got.restart()
	want := serviceModel{generation: 9, panelOpen: true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("restart state = %#v, want %#v", got, want)
	}
	got.callback(8, true)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("late callback changed restarted state: got %#v, want %#v", got, want)
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
