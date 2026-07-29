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

Prerequisites are a Noctalia v5 prerelease with plugin API 16, the `noctalia` CLI, this repository's `bitwarden-keyring` executable on `PATH`, and a valid, private `XDG_RUNTIME_DIR`.

### Remove a legacy installation first

This fail-closed cleanup is the first installation step. It deletes only the matching legacy shape: an absolute `HOME` is required; the legacy directory and its required metadata and entry files must be nonsymlinks; Python must validate plugin ID `noctalia-bitwarden-keyring` and version `4.0.0` in the legacy minimum-version field; and the directory's real path must equal the expected path. Otherwise it performs no deletion.

```bash
case ${HOME-} in /*) ;; *) printf '%s\n' 'HOME must be absolute' >&2; exit 1 ;; esac
legacy="$HOME/.config/noctalia/plugins/bitwarden-keyring"
metadata_name='manifest.'"json"
entry_name='Main.'"qml"
if [ ! -L "$legacy" ] && [ -d "$legacy" ] &&
   [ ! -L "$legacy/$metadata_name" ] && [ -f "$legacy/$metadata_name" ] &&
   [ ! -L "$legacy/$entry_name" ] && [ -f "$legacy/$entry_name" ] &&
   python3 - "$legacy/$metadata_name" <<'PY'
import json, pathlib, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text())
raise SystemExit(0 if value.get("id") == "noctalia-bitwarden-keyring" and value.get("min" + "NoctaliaVersion") == "4.0.0" else 1)
PY
then
  [ "$(realpath -- "$legacy")" = "$legacy" ] && rm -rf -- "$legacy"
fi
```

### Register and run

Run these repeatable commands from the repository root:

```bash
cd "$(git rev-parse --show-toplevel)" || exit 1
sources=$(noctalia msg plugins source list) || exit 1
if printf '%s\n' "$sources" | grep -Fqx "bitwarden-keyring path $PWD"; then
  :
elif printf '%s\n' "$sources" | grep -Eq '^bitwarden-keyring([[:space:]]|$)'; then
  printf '%s\n' 'Source bitwarden-keyring points elsewhere; repoint it in Noctalia settings.' >&2
  exit 1
else
  noctalia msg plugins source add bitwarden-keyring path "$PWD"
fi
noctalia msg plugins enable frap129/noctalia-bitwarden-keyring
bitwarden-keyring --noctalia --noctalia-timeout=2m
```

The plugin service and panel use a mode `0600` descriptor in `XDG_RUNTIME_DIR` to reach a short-lived authenticated loopback HTTP endpoint. Noctalia CLI IPC carries only a request ID; polling and cleanup complete the exchange. Passwords are never placed in process arguments, logged, or persisted.

The backend `--noctalia-timeout` remains available and defaults to `2m`; the v4 plugin timeout was removed. The old panel display, password-reveal, and animation settings were removed. Current settings default to `show_bitwarden_icon=true`, `auto_close_on_success=true`, and `auto_close_on_cancel=true`.

Noctalia mode can also be selected with `bitwarden-keyring --noctalia` or `BITWARDEN_KEYRING_NOCTALIA=1 bitwarden-keyring`. See [`noctalia-bitwarden-keyring/README.md`](noctalia-bitwarden-keyring/README.md) for plugin details.

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
