# bitwarden-keyring

A D-Bus service that implements the [Secret Service API](https://specifications.freedesktop.org/secret-service/) using Bitwarden as the backend. This allows any application using libsecret (git, Chrome, GNOME apps, etc.) to use your Bitwarden vault for credential storage.

## Requirements

- [Bitwarden CLI](https://bitwarden.com/help/cli/) installed and logged in
- One of: noctalia-bitwarden-keyring, zenity, kdialog, rofi, dmenu, or systemd-ask-password (for password prompts)

## Installation

### Arch Linux

```bash
makepkg -si
```

### Manual

```bash
go build -o bitwarden-keyring ./cmd/bitwarden-keyring
sudo cp bitwarden-keyring /usr/bin/
cp dist/org.freedesktop.secrets.service ~/.local/share/dbus-1/services/
```

## Usage

The service starts automatically via D-Bus activation when an application requests secrets. You can also start it manually:

```bash
bitwarden-keyring
```

Test with `secret-tool`:

```bash
# Store a secret
secret-tool store --label="Test" service example.com username joe

# Retrieve a secret
secret-tool lookup service example.com username joe
```

## Noctalia Integration

bitwarden-keyring supports [Noctalia](https://noctalia.org) for native panel-based password prompts.

### Enable Noctalia

Start bitwarden-keyring with the `--noctalia` flag:

```bash
bitwarden-keyring --noctalia
```

Or set the environment variable:

```bash
export BITWARDEN_KEYRING_NOCTALIA=1
bitwarden-keyring
```

### Requirements for Noctalia

1. The Noctalia plugin from this repository installed
2. Socket at `$XDG_RUNTIME_DIR/noctalia-keyring.sock` (created by the plugin)

### Optional: Dedicated Plugin

For a branded Bitwarden experience, you can install the Noctalia plugin from this repository.

#### Add Plugin Source

Add this repository to your Noctalia plugin sources in `~/.config/noctalia/plugins.json`:

```json
{
  "version": 1,
  "sources": [
    {
      "enabled": true,
      "name": "Official Noctalia Plugins",
      "url": "https://github.com/noctalia-dev/noctalia-plugins"
    },
    {
      "enabled": true,
      "name": "Bitwarden Keyring",
      "url": "https://github.com/frap129/bitwarden-keyring"
    }
  ],
  "states": {
    "bitwarden-keyring": {
      "enabled": true,
      "sourceUrl": "https://github.com/frap129/bitwarden-keyring"
    }
  }
}
```

For NixOS with Home Manager:

```nix
programs.noctalia-shell = {
  enable = true;
  plugins = {
    sources = [
      {
        enabled = true;
        name = "Official Noctalia Plugins";
        url = "https://github.com/noctalia-dev/noctalia-plugins";
      }
      {
        enabled = true;
        name = "Bitwarden Keyring";
        url = "https://github.com/frap129/bitwarden-keyring";
      }
    ];
    states = {
      bitwarden-keyring = {
        enabled = true;
        sourceUrl = "https://github.com/frap129/bitwarden-keyring";
      };
    };
    version = 1;
  };
};
```

#### Manual Installation

Alternatively, copy the plugin manually:

```bash
cp -r noctalia-plugin ~/.config/noctalia/plugins/bitwarden-keyring
```

Then enable the plugin in Noctalia settings. See [noctalia-plugin/README.md](noctalia-plugin/README.md) for details.

### Enabling Noctalia for the Systemd Service

When using D-Bus/systemd activation, you need to configure the service to enable Noctalia. There are two methods:

#### Method 1: Environment Variable (Recommended)

Create a systemd override that sets the environment variable:

```bash
mkdir -p ~/.config/systemd/user/bitwarden-keyring.service.d/
cat > ~/.config/systemd/user/bitwarden-keyring.service.d/noctalia.conf << 'EOF'
[Service]
Environment=BITWARDEN_KEYRING_NOCTALIA=1
EOF
systemctl --user daemon-reload
```

#### Method 2: ExecStart Override

Alternatively, override the ExecStart directive:

```bash
mkdir -p ~/.config/systemd/user/bitwarden-keyring.service.d/
cat > ~/.config/systemd/user/bitwarden-keyring.service.d/noctalia.conf << 'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/bitwarden-keyring --noctalia
EOF
systemctl --user daemon-reload
```

#### Applying Changes

After creating or modifying the override, reload and restart the service:

```bash
systemctl --user daemon-reload
systemctl --user restart bitwarden-keyring.service
```

### Fallback Behavior

When `--noctalia` is set but the agent is unavailable, bitwarden-keyring falls back to standard prompts (zenity, kdialog, rofi, dmenu, systemd-ask-password).

## Command-Line Options

| Flag                 | Default | Description                    |
| -------------------- | ------- | ------------------------------ |
| `--port`             | 8087    | Port for Bitwarden serve API   |
| `--debug`            | false   | Enable debug logging           |
| `--noctalia`         | false   | Enable Noctalia UI integration |
| `--noctalia-socket`  | (auto)  | Custom Noctalia socket path    |
| `--noctalia-timeout` | 120s    | Noctalia prompt timeout        |

## License

MIT
