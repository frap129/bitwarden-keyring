# bitwarden-keyring

A D-Bus service that implements the [Secret Service API](https://specifications.freedesktop.org/secret-service/) (`org.freedesktop.secrets`) and an SSH agent, backed by Bitwarden.
Apps using libsecret (git, browsers, GNOME apps, etc.) can store and retrieve credentials from your Bitwarden vault, and SSH keys can be served from Bitwarden SSH Key items.

## Requirements

- [Bitwarden CLI](https://bitwarden.com/help/cli/) (`bw`) installed and logged in
- A prompt backend for unlocking the vault:
  - Recommended: Noctalia + plugin in `noctalia-bitwarden-keyring/`
  - Or: `zenity`, `kdialog`, `rofi`, `systemd-ask-password`
  - `dmenu` is only used with `--allow-insecure-prompts`

## Installation

Arch Linux:

```bash
makepkg -si
```

Manual (system-wide, matches `dist/org.freedesktop.secrets.service`):

```bash
go build -o bitwarden-keyring ./cmd/bitwarden-keyring
sudo install -Dm755 bitwarden-keyring /usr/bin/bitwarden-keyring
sudo install -Dm644 dist/org.freedesktop.secrets.service /usr/share/dbus-1/services/org.freedesktop.secrets.service
```

User install (no root): copy `dist/org.freedesktop.secrets.service` to `~/.local/share/dbus-1/services/` and update its `Exec=` path to wherever you installed `bitwarden-keyring`.

Optional systemd user unit (often used with D-Bus activation): `dist/bitwarden-keyring.service`.

## Usage

Normally you don't start it manually: it autostarts via D-Bus activation when an app requests `org.freedesktop.secrets`.

Quick test:

```bash
# Store a secret
secret-tool store --label="Test" service example.com username joe

# Retrieve a secret
secret-tool lookup service example.com username joe
```

Debug run:

```bash
bitwarden-keyring --debug
```

## Prompts (Noctalia)

Enable Noctalia prompts:

```bash
bitwarden-keyring --noctalia
# or:
BITWARDEN_KEYRING_NOCTALIA=1 bitwarden-keyring
```

Install the Noctalia plugin from this repo:

```bash
mkdir -p ~/.config/noctalia/plugins
cp -r noctalia-bitwarden-keyring ~/.config/noctalia/plugins/bitwarden-keyring
```

Details: `noctalia-bitwarden-keyring/README.md`.

## Conflicts

Only one service can own `org.freedesktop.secrets`. Disable/uninstall other Secret Service providers (e.g. `gnome-keyring`, `kwalletd`, `keepassxc` Secret Service integration).

## Configuration

Full flag list: `bitwarden-keyring --help`.

- Components:
  - `--components=secrets` (Secret Service only)
  - `--components=ssh` (SSH agent only)
  - Default is `secrets,ssh`; if both are enabled and one fails to start, the process exits
- Bitwarden API port:
  - `--bw-port <port>` (preferred)
  - `--port <port>` is deprecated (compat)
- Session persistence:
  - Prefer setting `BW_SESSION` (if you manage sessions externally)
  - Or use `--session-store=file` and `--session-file <path>`

If running under systemd and `bw` is not found, add PATH via an override:

```bash
systemctl --user edit bitwarden-keyring.service
```

Baseline unit: `dist/bitwarden-keyring.service`.

## Troubleshooting

- "name already owned": another provider owns `org.freedesktop.secrets` (see Conflicts)
- no prompt shows up: install/configure a prompt backend (or Noctalia plugin)
- service starts then exits under systemd: ensure `bw` is in the service PATH; consider `--components=secrets`
- breaking CLI changes: `CHANGELOG.md`

## License

MIT
