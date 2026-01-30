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

### Custom PATH for Bitwarden CLI

If your `bw` executable is not in a system-defined path (like `.local/bin` or `.bun/bin`), you can add a custom PATH in a systemd override:

```bash
mkdir -p ~/.config/systemd/user/bitwarden-keyring.service.d/
cat > ~/.config/systemd/user/bitwarden-keyring.service.d/path.conf << 'EOF'
[Service]
Environment=PATH=%h/.bun/bin:%h/.local/bin:/usr/local/bin:/usr/bin:/bin
EOF
systemctl --user daemon-reload
```

### Fallback Behavior

When `--noctalia` is set but the agent is unavailable, bitwarden-keyring falls back to standard prompts (zenity, kdialog, rofi, dmenu, systemd-ask-password).

## SSH Agent

bitwarden-keyring can act as an SSH agent, serving keys stored in your Bitwarden vault.

### Enable SSH Agent

By default, both the secrets and SSH components are enabled. To run only specific components:

```bash
# Run only SSH agent (no D-Bus Secret Service)
bitwarden-keyring --components=ssh

# Run only secrets (no SSH agent)
bitwarden-keyring --components=secrets

# Run both (default behavior)
bitwarden-keyring
```

**Note:** When both components are enabled (default), both must start successfully or the service will exit.

### Verify It Works

```bash
# List available keys
ssh-add -l

# Test connection
ssh -T git@github.com
```

### Storing SSH Keys in Bitwarden

SSH keys must be stored as dedicated SSH Key items in Bitwarden (not as secure notes or attachments):

1. Open Bitwarden web vault or desktop app
2. Create new item -> Select "SSH Key" type
3. Paste your private key (and optionally public key)
4. Save

### Adding Keys via ssh-add

You can also add keys directly from the command line using `ssh-add`:

```bash
# Add a key (will be stored in Bitwarden)
ssh-add ~/.ssh/id_ed25519

# List keys to verify
ssh-add -l

# Remove a specific key (will delete from Bitwarden)
ssh-add -d ~/.ssh/id_ed25519.pub
```

**Important Notes:**
- When you add a key via `ssh-add`, it creates a new SSH Key item in your Bitwarden vault
- The private key is stored unencrypted in Bitwarden (encrypted at rest by Bitwarden's encryption)
- Removing a key with `ssh-add -d` permanently deletes it from your Bitwarden vault

### Limitations

- **No RemoveAll**: `ssh-add -D` (remove all keys) is not supported to prevent accidental deletion
- **Options ignored**: `ssh-add -t` (lifetime) and `-c` (confirm) options are silently ignored
- **Vault lock = Agent lock**: Locking the Bitwarden vault locks the agent
- **Encrypted keys**: Private keys with passphrases must be unlocked before adding (ssh-add prompts for this)

### System Configuration

To make the SSH agent available system-wide, create an environment.d file:

```bash
# For system-wide (all users)
sudo tee /etc/environment.d/50-bitwarden-ssh-agent.conf << 'EOF'
SSH_AUTH_SOCK=${XDG_RUNTIME_DIR}/bitwarden-keyring/ssh.sock
EOF

# Or for current user only
mkdir -p ~/.config/environment.d
cat > ~/.config/environment.d/50-bitwarden-ssh-agent.conf << 'EOF'
SSH_AUTH_SOCK=${XDG_RUNTIME_DIR}/bitwarden-keyring/ssh.sock
EOF
```

Log out and back in for the change to take effect.

### Enabling SSH Agent for Systemd Service

To disable the SSH component when using D-Bus activation, create a systemd override:

```bash
mkdir -p ~/.config/systemd/user/bitwarden-keyring.service.d/
cat > ~/.config/systemd/user/bitwarden-keyring.service.d/secrets-only.conf << 'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/bitwarden-keyring --components=secrets
EOF
systemctl --user daemon-reload
```

## Command-Line Options

| Flag                 | Default | Description                                      |
| -------------------- | ------- | ------------------------------------------------ |
| `--port`             | 8087    | Port for Bitwarden serve API                     |
| `--debug`            | false   | Enable debug logging                             |
| `--noctalia`         | false   | Enable Noctalia UI integration                   |
| `--noctalia-socket`  | (auto)  | Custom Noctalia socket path                      |
| `--noctalia-timeout` | 120s    | Noctalia prompt timeout                          |
| `--components`       | all     | Components to enable (comma-separated: secrets,ssh) |
| `--ssh-socket`       | (auto)  | Custom SSH agent socket path                     |

## License

MIT
