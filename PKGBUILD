# Maintainer: Joe Maples <joe@maples.dev>
pkgname=bitwarden-keyring
pkgver=0.4.0
pkgrel=1
pkgdesc="A D-Bus service implementing the Secret Service API using Bitwarden as the backend"
arch=('x86_64' 'aarch64')
url="https://github.com/joe/bitwarden-keyring"
license=('MIT')
makedepends=('go')
optdepends=(
    'bitwarden-cli: Required, can be installed via npm'
    'zenity: GTK password prompt'
    'kdialog: KDE password prompt'
    'rofi: password prompt for tiling WMs'
    'noctalia-shell: Native panel-based password prompts'
)
provides=('secret-service')
conflicts=('gnome-keyring' 'kwalletd' 'keepassxc')
backup=()
source=()
sha256sums=()

build() {
    cd "$srcdir/.."
    export CGO_CPPFLAGS="${CPPFLAGS}"
    export CGO_CFLAGS="${CFLAGS}"
    export CGO_CXXFLAGS="${CXXFLAGS}"
    export CGO_LDFLAGS="${LDFLAGS}"
    export GOFLAGS="-buildmode=pie -trimpath -ldflags=-linkmode=external -mod=readonly -modcacherw"

    go build -o "$pkgname" -ldflags "-X main.version=${pkgver}" ./cmd/bitwarden-keyring
}

package() {
    cd "$srcdir/.."

    # Install binary
    install -Dm755 "$pkgname" "$pkgdir/usr/bin/$pkgname"

    # Install D-Bus service file for activation
    install -Dm644 dist/org.freedesktop.secrets.service \
        "$pkgdir/usr/share/dbus-1/services/org.freedesktop.secrets.service"

    # Install systemd user service
    install -Dm644 dist/bitwarden-keyring.service \
        "$pkgdir/usr/lib/systemd/user/bitwarden-keyring.service"

    # Install README
    install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
}
