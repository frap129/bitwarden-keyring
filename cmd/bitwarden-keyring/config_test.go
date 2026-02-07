package main

import (
	"strings"
	"testing"
	"time"
)

func TestSelectPort(t *testing.T) {
	tests := []struct {
		name            string
		bwPortFlag      int
		deprecatedPort  int
		wantErr         bool
		wantPortNonZero bool
		wantExactPort   int
	}{
		{
			name:            "auto-select when both zero",
			bwPortFlag:      0,
			deprecatedPort:  0,
			wantErr:         false,
			wantPortNonZero: true,
		},
		{
			name:           "use bw-port when set",
			bwPortFlag:     8087,
			deprecatedPort: 0,
			wantErr:        false,
			wantExactPort:  8087,
		},
		{
			name:           "use deprecated port when bw-port not set",
			bwPortFlag:     0,
			deprecatedPort: 9090,
			wantErr:        false,
			wantExactPort:  9090,
		},
		{
			name:           "bw-port takes precedence over deprecated",
			bwPortFlag:     8087,
			deprecatedPort: 9090,
			wantErr:        false,
			wantExactPort:  8087,
		},
		{
			name:           "valid port range - low",
			bwPortFlag:     1,
			deprecatedPort: 0,
			wantErr:        false,
			wantExactPort:  1,
		},
		{
			name:           "valid port range - high",
			bwPortFlag:     65535,
			deprecatedPort: 0,
			wantErr:        false,
			wantExactPort:  65535,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectPort(tt.bwPortFlag, tt.deprecatedPort)

			if (err != nil) != tt.wantErr {
				t.Errorf("selectPort() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantPortNonZero && got == 0 {
				t.Errorf("selectPort() = %d, want non-zero port", got)
			}

			if tt.wantExactPort != 0 && got != tt.wantExactPort {
				t.Errorf("selectPort() = %d, want %d", got, tt.wantExactPort)
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name           string
		config         Config
		wantErr        bool
		wantErrContain string
	}{
		{
			name: "valid config with defaults",
			config: Config{
				BWPort:             8087,
				SessionStore:       "memory",
				MaxPasswordRetries: 3,
			},
			wantErr: false,
		},
		{
			name: "valid config with file store",
			config: Config{
				BWPort:             8087,
				SessionStore:       "file",
				MaxPasswordRetries: 3,
			},
			wantErr: false,
		},
		{
			name: "valid config with systemd path",
			config: Config{
				BWPort:                 8087,
				SessionStore:           "memory",
				SystemdAskPasswordPath: "/usr/bin/systemd-ask-password",
			},
			wantErr: false,
		},
		{
			name: "invalid session store",
			config: Config{
				BWPort:       8087,
				SessionStore: "invalid",
			},
			wantErr:        true,
			wantErrContain: "session-store must be",
		},
		{
			name: "relative systemd path",
			config: Config{
				BWPort:                 8087,
				SessionStore:           "memory",
				SystemdAskPasswordPath: "relative/path",
			},
			wantErr:        true,
			wantErrContain: "must be an absolute path",
		},
		{
			name: "relative systemd path with dot",
			config: Config{
				BWPort:                 8087,
				SessionStore:           "memory",
				SystemdAskPasswordPath: "./some/path",
			},
			wantErr:        true,
			wantErrContain: "must be an absolute path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(&tt.config)

			if (err != nil) != tt.wantErr {
				t.Errorf("validateConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErrContain != "" && err != nil {
				if !strings.Contains(err.Error(), tt.wantErrContain) {
					t.Errorf("validateConfig() error = %v, want error containing %q", err, tt.wantErrContain)
				}
			}
		})
	}
}

func TestConfigFromArgs(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		wantErr        bool
		wantErrContain string
		wantHelp       bool
		checkFunc      func(t *testing.T, cfg Config)
	}{
		{
			name:    "default config",
			args:    []string{},
			wantErr: false,
			checkFunc: func(t *testing.T, cfg Config) {
				if cfg.BWPort == 0 {
					t.Error("expected auto-selected port, got 0")
				}
				if cfg.BWStartTimeout != 10*time.Second {
					t.Errorf("BWStartTimeout = %v, want %v", cfg.BWStartTimeout, 10*time.Second)
				}
				if cfg.SessionStore != "memory" {
					t.Errorf("SessionStore = %s, want memory", cfg.SessionStore)
				}
				if cfg.MaxPasswordRetries != 3 {
					t.Errorf("MaxPasswordRetries = %d, want 3", cfg.MaxPasswordRetries)
				}
				if !cfg.EnabledComponents["secrets"] || !cfg.EnabledComponents["ssh"] {
					t.Error("expected all components enabled by default")
				}
			},
		},
		{
			name:    "explicit bw-port",
			args:    []string{"--bw-port=9090"},
			wantErr: false,
			checkFunc: func(t *testing.T, cfg Config) {
				if cfg.BWPort != 9090 {
					t.Errorf("BWPort = %d, want 9090", cfg.BWPort)
				}
			},
		},
		{
			name:    "enable debug",
			args:    []string{"--debug"},
			wantErr: false,
			checkFunc: func(t *testing.T, cfg Config) {
				if !cfg.Debug {
					t.Error("Debug = false, want true")
				}
			},
		},
		{
			name:    "enable noctalia",
			args:    []string{"--noctalia"},
			wantErr: false,
			checkFunc: func(t *testing.T, cfg Config) {
				if !cfg.NoctaliaEnabled {
					t.Error("NoctaliaEnabled = false, want true")
				}
			},
		},
		{
			name:    "custom components",
			args:    []string{"--components=secrets"},
			wantErr: false,
			checkFunc: func(t *testing.T, cfg Config) {
				if !cfg.EnabledComponents["secrets"] {
					t.Error("secrets component not enabled")
				}
				if cfg.EnabledComponents["ssh"] {
					t.Error("ssh component should not be enabled")
				}
			},
		},
		{
			name:           "invalid component",
			args:           []string{"--components=invalid"},
			wantErr:        true,
			wantErrContain: "invalid --components flag",
		},
		{
			name:     "help flag",
			args:     []string{"--help"},
			wantErr:  true,
			wantHelp: true,
		},
		{
			name:           "invalid session store",
			args:           []string{"--session-store=invalid"},
			wantErr:        true,
			wantErrContain: "session-store must be",
		},
		{
			name:           "relative systemd path",
			args:           []string{"--systemd-ask-password-path=relative/path"},
			wantErr:        true,
			wantErrContain: "must be an absolute path",
		},
		{
			name:    "custom bw-start-timeout",
			args:    []string{"--bw-start-timeout=30s"},
			wantErr: false,
			checkFunc: func(t *testing.T, cfg Config) {
				if cfg.BWStartTimeout != 30*time.Second {
					t.Errorf("BWStartTimeout = %v, want 30s", cfg.BWStartTimeout)
				}
			},
		},
		{
			name:    "enable debug-http",
			args:    []string{"--debug-http"},
			wantErr: false,
			checkFunc: func(t *testing.T, cfg Config) {
				if !cfg.DebugHTTP {
					t.Error("DebugHTTP = false, want true")
				}
			},
		},
		{
			name:    "custom noctalia-socket",
			args:    []string{"--noctalia-socket=/tmp/test.sock"},
			wantErr: false,
			checkFunc: func(t *testing.T, cfg Config) {
				if cfg.NoctaliaSocket != "/tmp/test.sock" {
					t.Errorf("NoctaliaSocket = %s, want /tmp/test.sock", cfg.NoctaliaSocket)
				}
			},
		},
		{
			name:    "custom noctalia-timeout",
			args:    []string{"--noctalia-timeout=60s"},
			wantErr: false,
			checkFunc: func(t *testing.T, cfg Config) {
				if cfg.NoctaliaTimeout != 60*time.Second {
					t.Errorf("NoctaliaTimeout = %v, want 60s", cfg.NoctaliaTimeout)
				}
			},
		},
		{
			name:    "enable allow-insecure-prompts",
			args:    []string{"--allow-insecure-prompts"},
			wantErr: false,
			checkFunc: func(t *testing.T, cfg Config) {
				if !cfg.AllowInsecurePrompts {
					t.Error("AllowInsecurePrompts = false, want true")
				}
			},
		},
		{
			name:    "custom ssh-socket",
			args:    []string{"--ssh-socket=/tmp/ssh.sock"},
			wantErr: false,
			checkFunc: func(t *testing.T, cfg Config) {
				if cfg.SSHSocketPath != "/tmp/ssh.sock" {
					t.Errorf("SSHSocketPath = %s, want /tmp/ssh.sock", cfg.SSHSocketPath)
				}
			},
		},
		{
			name:    "enable no-ssh-env-export",
			args:    []string{"--no-ssh-env-export"},
			wantErr: false,
			checkFunc: func(t *testing.T, cfg Config) {
				if !cfg.NoSSHEnvExport {
					t.Error("NoSSHEnvExport = false, want true")
				}
			},
		},
		{
			name:    "custom max-password-retries",
			args:    []string{"--max-password-retries=5"},
			wantErr: false,
			checkFunc: func(t *testing.T, cfg Config) {
				if cfg.MaxPasswordRetries != 5 {
					t.Errorf("MaxPasswordRetries = %d, want 5", cfg.MaxPasswordRetries)
				}
			},
		},
		{
			name:    "custom session-file",
			args:    []string{"--session-file=/tmp/session"},
			wantErr: false,
			checkFunc: func(t *testing.T, cfg Config) {
				if cfg.SessionFile != "/tmp/session" {
					t.Errorf("SessionFile = %s, want /tmp/session", cfg.SessionFile)
				}
			},
		},
		{
			name:    "deprecated port flag",
			args:    []string{"--port=9090"},
			wantErr: false,
			checkFunc: func(t *testing.T, cfg Config) {
				if cfg.BWPort != 9090 {
					t.Errorf("BWPort = %d, want 9090", cfg.BWPort)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ConfigFromArgs(tt.args)

			if tt.wantHelp {
				// Help returns an error but we don't want to fail
				return
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("ConfigFromArgs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErrContain != "" && err != nil {
				if !strings.Contains(err.Error(), tt.wantErrContain) {
					t.Errorf("ConfigFromArgs() error = %v, want error containing %q", err, tt.wantErrContain)
				}
			}

			if tt.checkFunc != nil && !tt.wantErr {
				tt.checkFunc(t, cfg)
			}
		})
	}
}

func TestEnabledComponentsList(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		wantList []string
	}{
		{
			name: "both components enabled",
			config: Config{
				EnabledComponents: map[string]bool{
					"secrets": true,
					"ssh":     true,
				},
			},
			wantList: []string{"secrets", "ssh"},
		},
		{
			name: "only secrets enabled",
			config: Config{
				EnabledComponents: map[string]bool{
					"secrets": true,
				},
			},
			wantList: []string{"secrets"},
		},
		{
			name: "only ssh enabled",
			config: Config{
				EnabledComponents: map[string]bool{
					"ssh": true,
				},
			},
			wantList: []string{"ssh"},
		},
		{
			name: "no components enabled",
			config: Config{
				EnabledComponents: map[string]bool{},
			},
			wantList: []string{},
		},
		{
			name: "nil components map",
			config: Config{
				EnabledComponents: nil,
			},
			wantList: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.EnabledComponentsList()

			if len(got) != len(tt.wantList) {
				t.Errorf("EnabledComponentsList() length = %d, want %d", len(got), len(tt.wantList))
				return
			}

			for i, v := range got {
				if v != tt.wantList[i] {
					t.Errorf("EnabledComponentsList()[%d] = %s, want %s", i, v, tt.wantList[i])
				}
			}
		})
	}
}

func TestSessionConfigMapping(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{
			name: "noctalia enabled",
			config: Config{
				NoctaliaEnabled: true,
			},
		},
		{
			name: "noctalia disabled",
			config: Config{
				NoctaliaEnabled: false,
			},
		},
		{
			name: "allow insecure prompts enabled",
			config: Config{
				AllowInsecurePrompts: true,
			},
		},
		{
			name: "allow insecure prompts disabled",
			config: Config{
				AllowInsecurePrompts: false,
			},
		},
		{
			name: "full session config mapping",
			config: Config{
				NoctaliaEnabled:        true,
				NoctaliaSocket:         "/tmp/noctalia.sock",
				NoctaliaTimeout:        60 * time.Second,
				AllowInsecurePrompts:   true,
				SystemdAskPasswordPath: "/usr/bin/systemd-ask-password",
				SessionStore:           "file",
				SessionFile:            "/tmp/session",
				MaxPasswordRetries:     5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := tt.config.SessionConfig()

			// Verify all fields are correctly mapped
			if sc.NoctaliaEnabled != tt.config.NoctaliaEnabled {
				t.Errorf("NoctaliaEnabled = %v, want %v", sc.NoctaliaEnabled, tt.config.NoctaliaEnabled)
			}
			if sc.NoctaliaSocket != tt.config.NoctaliaSocket {
				t.Errorf("NoctaliaSocket = %s, want %s", sc.NoctaliaSocket, tt.config.NoctaliaSocket)
			}
			if sc.NoctaliaTimeout != tt.config.NoctaliaTimeout {
				t.Errorf("NoctaliaTimeout = %v, want %v", sc.NoctaliaTimeout, tt.config.NoctaliaTimeout)
			}
			if sc.AllowInsecurePrompts != tt.config.AllowInsecurePrompts {
				t.Errorf("AllowInsecurePrompts = %v, want %v", sc.AllowInsecurePrompts, tt.config.AllowInsecurePrompts)
			}
			if sc.SystemdAskPasswordPath != tt.config.SystemdAskPasswordPath {
				t.Errorf("SystemdAskPasswordPath = %s, want %s", sc.SystemdAskPasswordPath, tt.config.SystemdAskPasswordPath)
			}
			if sc.SessionStore != tt.config.SessionStore {
				t.Errorf("SessionStore = %s, want %s", sc.SessionStore, tt.config.SessionStore)
			}
			if sc.SessionFile != tt.config.SessionFile {
				t.Errorf("SessionFile = %s, want %s", sc.SessionFile, tt.config.SessionFile)
			}
			if sc.MaxPasswordRetries != tt.config.MaxPasswordRetries {
				t.Errorf("MaxPasswordRetries = %d, want %d", sc.MaxPasswordRetries, tt.config.MaxPasswordRetries)
			}
		})
	}
}

func TestConfigFromArgs_NoctaliaEnv(t *testing.T) {
	t.Setenv("BITWARDEN_KEYRING_NOCTALIA", "1")

	cfg, err := ConfigFromArgs([]string{})
	if err != nil {
		t.Fatalf("ConfigFromArgs() error = %v", err)
	}

	if !cfg.NoctaliaEnabled {
		t.Error("NoctaliaEnabled = false, want true when env var is set")
	}
}

func TestConfigFromArgs_NoctaliaEnvNotSet(t *testing.T) {
	t.Setenv("BITWARDEN_KEYRING_NOCTALIA", "")

	cfg, err := ConfigFromArgs([]string{})
	if err != nil {
		t.Fatalf("ConfigFromArgs() error = %v", err)
	}

	if cfg.NoctaliaEnabled {
		t.Error("NoctaliaEnabled = true, want false when env var is not set")
	}
}

func TestConfig_Version(t *testing.T) {
	cfg, err := ConfigFromArgs([]string{})
	if err != nil {
		t.Fatalf("ConfigFromArgs() error = %v", err)
	}

	if cfg.Version != version {
		t.Errorf("Version = %s, want %s", cfg.Version, version)
	}
}
