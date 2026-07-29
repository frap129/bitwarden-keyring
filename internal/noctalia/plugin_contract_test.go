package noctalia

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestV5PluginSourceContract(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	repoDir := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	pluginDir := filepath.Join(repoDir, "noctalia-bitwarden-keyring")

	requiredFiles := []string{"plugin.toml", "service.luau", "panel.luau", filepath.Join("translations", "en.json")}
	for _, name := range requiredFiles {
		if _, err := os.Stat(filepath.Join(pluginDir, name)); err != nil {
			t.Errorf("required plugin file %s: %v", name, err)
		}
	}

	legacyFiles := []string{"manifest.json", "Main.qml", "Panel.qml", "AuthDialog.qml", "Settings.qml"}
	for _, name := range legacyFiles {
		if _, err := os.Stat(filepath.Join(pluginDir, name)); err == nil {
			t.Errorf("legacy plugin file %s still exists", name)
		} else if !os.IsNotExist(err) {
			t.Errorf("check legacy plugin file %s: %v", name, err)
		}
	}

	for _, name := range []string{"service.luau", "panel.luau"} {
		contents, err := os.ReadFile(filepath.Join(pluginDir, name))
		if err != nil {
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

	manifest, err := os.ReadFile(filepath.Join(pluginDir, "plugin.toml"))
	if err == nil {
		manifestSource := string(manifest)
		for _, required := range []string{
			`id = "frap129/noctalia-bitwarden-keyring"`,
			`name = "Bitwarden Keyring"`,
			`version = "0.5.0"`,
			`plugin_api = 8`,
			`author = "frap129"`,
			`license = "MIT"`,
			`icon = "brand-bitwarden"`,
			`description = "Secure prompts for the Bitwarden-backed Secret Service and SSH agent."`,
			`tags = ["bitwarden", "password", "security"]`,
			`dependencies = ["bitwarden-keyring"]`,
			"[[service]]", `id = "service"`, `entry = "service.luau"`,
			"[[panel]]", `id = "unlock"`, `entry = "panel.luau"`, `width = 400`, `height = 300`,
			`placement = "floating"`, `position = "center"`, `open_near_click = false`, `dismiss_on_outside_click = false`,
			`key = "show_bitwarden_icon"`, `key = "auto_close_on_success"`, `key = "auto_close_on_cancel"`,
			`label_key = "settings.show_bitwarden_icon.label"`, `description_key = "settings.show_bitwarden_icon.description"`,
			`label_key = "settings.auto_close_on_success.label"`, `description_key = "settings.auto_close_on_success.description"`,
			`label_key = "settings.auto_close_on_cancel.label"`, `description_key = "settings.auto_close_on_cancel.description"`,
			`type = "bool"`, `default = true`,
		} {
			if !strings.Contains(manifestSource, required) {
				t.Errorf("plugin.toml does not contain %q", required)
			}
		}
		for _, forbidden := range []string{"keyboard_focus", "timeout", "panelMode"} {
			if strings.Contains(manifestSource, forbidden) {
				t.Errorf("plugin.toml contains forbidden literal %q", forbidden)
			}
		}
	}

	translations, err := os.ReadFile(filepath.Join(pluginDir, "translations", "en.json"))
	if err == nil {
		var document map[string]any
		if err := json.Unmarshal(translations, &document); err != nil {
			t.Errorf("parse translations/en.json: %v", err)
		}
	}
}
