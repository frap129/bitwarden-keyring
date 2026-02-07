package main

import (
	"strings"
	"testing"
)

func TestParseComponents(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantSecrets bool
		wantSSH     bool
		wantErr     bool
	}{
		{
			name:        "empty enables all",
			input:       "",
			wantSecrets: true,
			wantSSH:     true,
			wantErr:     false,
		},
		{
			name:        "secrets only",
			input:       "secrets",
			wantSecrets: true,
			wantSSH:     false,
			wantErr:     false,
		},
		{
			name:        "ssh only",
			input:       "ssh",
			wantSecrets: false,
			wantSSH:     true,
			wantErr:     false,
		},
		{
			name:        "both components",
			input:       "ssh,secrets",
			wantSecrets: true,
			wantSSH:     true,
			wantErr:     false,
		},
		{
			name:        "both components reversed order",
			input:       "secrets,ssh",
			wantSecrets: true,
			wantSSH:     true,
			wantErr:     false,
		},
		{
			name:        "whitespace handling",
			input:       " secrets , ssh ",
			wantSecrets: true,
			wantSSH:     true,
			wantErr:     false,
		},
		{
			name:        "leading comma",
			input:       ",secrets",
			wantSecrets: true,
			wantSSH:     false,
			wantErr:     false,
		},
		{
			name:        "trailing comma",
			input:       "ssh,",
			wantSecrets: false,
			wantSSH:     true,
			wantErr:     false,
		},
		{
			name:        "multiple commas",
			input:       "secrets,,ssh",
			wantSecrets: true,
			wantSSH:     true,
			wantErr:     false,
		},
		{
			name:    "unknown component",
			input:   "invalid",
			wantErr: true,
		},
		{
			name:    "valid and invalid mixed",
			input:   "secrets,invalid",
			wantErr: true,
		},
		{
			name:    "only commas",
			input:   ",,,",
			wantErr: true,
		},
		{
			name:    "only whitespace and commas",
			input:   " , , ",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseComponents(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseComponents(%q) expected error, got nil", tt.input)
				}
				return
			}

			if err != nil {
				t.Errorf("parseComponents(%q) unexpected error: %v", tt.input, err)
				return
			}

			if got["secrets"] != tt.wantSecrets {
				t.Errorf("parseComponents(%q) secrets = %v, want %v", tt.input, got["secrets"], tt.wantSecrets)
			}
			if got["ssh"] != tt.wantSSH {
				t.Errorf("parseComponents(%q) ssh = %v, want %v", tt.input, got["ssh"], tt.wantSSH)
			}
		})
	}
}

func TestConfigNoSSHEnvExport_DefaultsFalse(t *testing.T) {
	cfg := Config{}
	if cfg.NoSSHEnvExport {
		t.Error("NoSSHEnvExport should default to false")
	}
}

func TestValidComponentsList(t *testing.T) {
	list := validComponentsList()

	// Should be sorted alphabetically
	want := "secrets, ssh"
	if list != want {
		t.Errorf("validComponentsList() = %q, want %q", list, want)
	}
}

func TestRun_ConfigError(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		wantErrContain string
	}{
		{
			name:           "invalid component",
			args:           []string{"--components=invalid"},
			wantErrContain: "configuration error",
		},
		{
			name:           "invalid session store",
			args:           []string{"--session-store=invalid"},
			wantErrContain: "configuration error",
		},
		{
			name:           "relative systemd path",
			args:           []string{"--systemd-ask-password-path=relative/path"},
			wantErrContain: "configuration error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := run(tt.args)

			if err == nil {
				t.Error("run() expected error for invalid config, got nil")
				return
			}

			if !strings.Contains(err.Error(), tt.wantErrContain) {
				t.Errorf("run() error = %v, want error containing %q", err, tt.wantErrContain)
			}
		})
	}
}
