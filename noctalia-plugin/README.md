# Bitwarden Keyring Noctalia Plugin

A Noctalia plugin that provides a native UI for Bitwarden Keyring password prompts.

## Overview

This plugin integrates with [bitwarden-keyring](https://github.com/joe/bitwarden-keyring) to display password prompts through Noctalia's panel system when unlocking the Bitwarden vault.

## Requirements

- [Noctalia](https://noctalia.org) >= 3.6.0
- [noctalia-polkit-agent](https://github.com/anthonyhab/noctalia-unofficial-auth-agent) (provides the IPC socket)
- bitwarden-keyring running with `--noctalia` flag

## Installation

1. **Install and start the noctalia-polkit-agent**:
   ```bash
   # Build and install from source
   git clone https://github.com/anthonyhab/noctalia-unofficial-auth-agent
   cd noctalia-unofficial-auth-agent
   cmake -B build
   cmake --build build
   sudo cmake --install build

   # Enable the systemd service
   systemctl --user enable --now noctalia-polkit.service
   ```

2. **Install this plugin**:
   ```bash
   # Copy to Noctalia plugins directory
   mkdir -p ~/.config/noctalia/plugins
   cp -r noctalia-plugin ~/.config/noctalia/plugins/bitwarden-keyring
   ```

3. **Enable the plugin in Noctalia settings**

4. **Start bitwarden-keyring with Noctalia support**:
   ```bash
   bitwarden-keyring --noctalia
   ```

   Or enable via environment variable:
   ```bash
   export BITWARDEN_KEYRING_NOCTALIA=1
   bitwarden-keyring
   ```

## Configuration

The plugin can be configured through Noctalia's plugin settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `pollInterval` | 100 | How often to poll for requests (ms) |
| `timeout` | 120 | Request timeout in seconds |
| `showBitwardenIcon` | true | Show Bitwarden icon in the dialog |
| `autoCloseOnSuccess` | true | Auto-close panel after successful auth |
| `autoCloseOnCancel` | true | Auto-close panel on cancel |
| `panelMode` | "attached" | Panel display mode (attached/centered/window) |

## How It Works

1. When bitwarden-keyring needs a password, it sends a `keyring_request` to the noctalia-polkit-agent socket
2. The agent queues the request and emits it as an event with `source: "keyring"`
3. This plugin polls the agent, receives the request, and displays a password dialog
4. The user enters their password (or cancels)
5. The plugin sends the response back via the agent
6. The agent forwards the password to bitwarden-keyring

## Troubleshooting

### Plugin doesn't show password dialog

- Ensure noctalia-polkit-agent is running: `systemctl --user status noctalia-polkit.service`
- Check that the socket exists: `ls $XDG_RUNTIME_DIR/noctalia-polkit-agent.sock`
- Ensure bitwarden-keyring is started with `--noctalia` flag

### Password dialog appears but authentication fails

- Check bitwarden-keyring logs for errors
- Ensure your Bitwarden CLI is properly configured

## License

MIT
