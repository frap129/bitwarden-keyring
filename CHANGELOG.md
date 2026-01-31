## 0.4.0 (2026-01-31)

- chore: bump PKGBUILD ([2ed7bf2](https://github.com/frap129/bitwarden-keyring/commit/2ed7bf2))
- fix: improve auto-unlock thread-safety, testability, and consistency ([b2b30cf](https://github.com/frap129/bitwarden-keyring/commit/b2b30cf))
- fix(ssh): address code review issues for SSH agent ([470790f](https://github.com/frap129/bitwarden-keyring/commit/470790f))
- fix(systemd): Assume bin is in path, fix ssh socket creation ([e86a59a](https://github.com/frap129/bitwarden-keyring/commit/e86a59a))
- feat(cli)!: replace --ssh-agent with --component ([de8d603](https://github.com/frap129/bitwarden-keyring/commit/de8d603))
- fix(cli)!: rename --component to --components ([c6f1875](https://github.com/frap129/bitwarden-keyring/commit/c6f1875))

### BREAKING CHANGE

- --component has been renamed to --components.
- --ssh-agent removed; default enables secrets and ssh (use --component=secrets to disable ssh).

## 0.3.0 (2026-01-27)

- refactor: improve D-Bus Secret Service correctness and safety ([34505da](https://github.com/frap129/bitwarden-keyring/commit/34505da))
- refactor: rename noctalia-plugin to noctalia-bitwarden-keyring ([a720a4b](https://github.com/frap129/bitwarden-keyring/commit/a720a4b))
- refactor(noctalia): replace polling with SocketServer for push-based IPC ([5046539](https://github.com/frap129/bitwarden-keyring/commit/5046539))
- chore: bump version to 0.2.0 ([e2c4f94](https://github.com/frap129/bitwarden-keyring/commit/e2c4f94))
- chore: Remove plans ([c15a6f1](https://github.com/frap129/bitwarden-keyring/commit/c15a6f1))
- docs: add custom PATH workaround for systemd service ([04eb0aa](https://github.com/frap129/bitwarden-keyring/commit/04eb0aa))
- docs: add Noctalia plugin source configuration instructions ([ff4394e](https://github.com/frap129/bitwarden-keyring/commit/ff4394e))
- docs: add noctalia systemd service configuration guide ([0624b82](https://github.com/frap129/bitwarden-keyring/commit/0624b82))
- docs: remove incorrect optional requirement and add plugin registry ([e3d1402](https://github.com/frap129/bitwarden-keyring/commit/e3d1402))
- docs(README): Add plugin under requirements ([fa2326c](https://github.com/frap129/bitwarden-keyring/commit/fa2326c))
- fix: fail gracefully if bitwarden-cli is not installed ([8bf5bc6](https://github.com/frap129/bitwarden-keyring/commit/8bf5bc6))
- fix: registry.json ([af5e3fa](https://github.com/frap129/bitwarden-keyring/commit/af5e3fa))
- fix(noctalia): manifest.json ([cfc5799](https://github.com/frap129/bitwarden-keyring/commit/cfc5799))
- fix(prompt): handle user cancellation correctly across all prompt types ([1d3eb12](https://github.com/frap129/bitwarden-keyring/commit/1d3eb12))
- fix(systemd): allow Bitwarden CLI write access to config directory ([f9e2df6](https://github.com/frap129/bitwarden-keyring/commit/f9e2df6))
- build(PKGBUILD): Don't require bw be installed through pacman ([1140798](https://github.com/frap129/bitwarden-keyring/commit/1140798))
- feat: add Noctalia UI integration for password prompts ([9604508](https://github.com/frap129/bitwarden-keyring/commit/9604508))
- feat: initial implementation of bitwarden-keyring ([9d80f4d](https://github.com/frap129/bitwarden-keyring/commit/9d80f4d))
