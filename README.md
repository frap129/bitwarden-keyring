# bitwarden-keyring

A D-Bus service that implements the [Secret Service API](https://specifications.freedesktop.org/secret-service/) using Bitwarden as the backend. This allows any application using libsecret (git, Chrome, GNOME apps, etc.) to use your Bitwarden vault for credential storage.

## Requirements

- [Bitwarden CLI](https://bitwarden.com/help/cli/) installed and logged in
- One of: zenity, kdialog, or rofi (for password prompts)

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

## License

MIT
