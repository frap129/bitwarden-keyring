package noctalia

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
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

func TestV5PluginSourceContract(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	pluginDir := filepath.Join(filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..")), "noctalia-bitwarden-keyring")

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

func assertPluginManifest(t *testing.T, got pluginManifest) {
	t.Helper()
	wantRoot := map[string]any{
		"id": "frap129/noctalia-bitwarden-keyring", "name": "Bitwarden Keyring", "version": "0.5.0", "plugin_api": 8,
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
