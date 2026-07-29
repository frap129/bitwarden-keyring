# Bitwarden Keyring Noctalia Plugin

This plugin provides Noctalia's service and panel for secure Bitwarden Keyring prompts.

## Prerequisites

- Noctalia v5 prerelease with plugin API 16
- The `noctalia` CLI
- This repository's `bitwarden-keyring` executable on `PATH`
- A valid, private `XDG_RUNTIME_DIR`

## Remove a legacy installation first

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

## Register and run

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

## Security and lifecycle

The service reads a mode `0600` descriptor from `XDG_RUNTIME_DIR` and uses its short-lived authenticated loopback HTTP endpoint. Noctalia CLI IPC carries only a request ID. The service polls for the request and result, then both sides clean up request state and the descriptor. Passwords are never placed in process arguments, logged, or persisted.

The backend `--noctalia-timeout` still bounds the prompt (default `2m`), but the v4 plugin timeout was removed. The former panel display, password-reveal, and animation settings were also removed.

| Setting | Default |
| --- | --- |
| `show_bitwarden_icon` | `true` |
| `auto_close_on_success` | `true` |
| `auto_close_on_cancel` | `true` |

## License

MIT
