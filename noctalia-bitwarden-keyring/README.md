# Bitwarden Keyring Noctalia Plugin

A Noctalia plugin that provides a native UI for Bitwarden Keyring password prompts.

## Overview

This plugin integrates with [bitwarden-keyring](https://github.com/frap129/bitwarden-keyring) to display password prompts through Noctalia's panel system when unlocking the Bitwarden vault.

## Requirements

- [Noctalia](https://noctalia.org) >= 4.0.0
- bitwarden-keyring running with `--noctalia` flag

## Installation

1. **Install this plugin**:

   ```bash
   # Copy to Noctalia plugins directory
   mkdir -p ~/.config/noctalia/plugins
   cp -r noctalia-plugin ~/.config/noctalia/plugins/bitwarden-keyring
   ```

2. **Enable the plugin in Noctalia settings**

3. **Start bitwarden-keyring with Noctalia support**:

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

| Setting              | Default    | Description                                   |
| -------------------- | ---------- | --------------------------------------------- |
| `timeout`            | 120        | Request timeout in seconds                    |
| `showBitwardenIcon`  | true       | Show Bitwarden icon in the dialog             |
| `autoCloseOnSuccess` | true       | Auto-close panel after successful auth        |
| `autoCloseOnCancel`  | true       | Auto-close panel on cancel                    |
| `panelMode`          | "attached" | Panel display mode (attached/centered/window) |

## How It Works

1. The plugin creates a socket server at `$XDG_RUNTIME_DIR/noctalia-keyring.sock`
2. When bitwarden-keyring needs a password, it connects directly to this socket
3. The plugin receives the request and displays a password dialog
4. The user enters their password (or cancels)
5. The plugin sends the response back on the same connection
6. bitwarden-keyring receives the password and proceeds

This is a push-based architecture - the plugin responds instantly to incoming requests without any polling.

## Troubleshooting

### Plugin doesn't show password dialog

- Check that the socket exists: `ls $XDG_RUNTIME_DIR/noctalia-keyring.sock`
- Ensure bitwarden-keyring is started with `--noctalia` flag
- Check Noctalia logs for any plugin errors

### Password dialog appears but authentication fails

- Check bitwarden-keyring logs for errors
- Ensure your Bitwarden CLI is properly configured

## License

MIT
