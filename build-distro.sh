#!/usr/bin/env bash
#===============================================================================
# b3nsecu Distro-Builder
#-------------------------------------------------------------------------------
# Baut eine bootbare Debian-12-ISO mit vorinstalliertem Security-Stack.
# Voraussetzungen: live-build, debootstrap (apt install live-build debootstrap)
#
# Nutzung:
#   sudo ./build-distro.sh                    # ISO mit Profil 'full'
#   sudo ./build-distro.sh --profile=firewall # ISO nur mit Firewall-Stack
#===============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
PROFILE="full"
VERSION="$(cat "${SCRIPT_DIR}/VERSION" 2>/dev/null || echo "1.0.0")"

log()  { echo -e "\033[0;34m[BUILD]\033[0m $*"; }
ok()   { echo -e "\033[0;32m[ OK  ]\033[0m $*"; }
die()  { echo -e "\033[0;31m[FEHLER]\033[0m $*" >&2; exit 1; }

#-------------------------------------------------------------------------------
# Voraussetzungen pruefen
#-------------------------------------------------------------------------------
check_prerequisites() {
    [[ $EUID -eq 0 ]] || die "Bitte als root ausfuehren (sudo ./build-distro.sh)"
    for cmd in lb debootstrap git; do
        command -v "$cmd" >/dev/null || die "'$cmd' fehlt. Installation: apt install live-build debootstrap git"
    done
    log "Voraussetzungen erfuellt."
}

#-------------------------------------------------------------------------------
# Live-Build konfigurieren
#-------------------------------------------------------------------------------
configure_live_build() {
    log "Konfiguriere live-build (Profil: ${PROFILE})..."
    mkdir -p "${BUILD_DIR}"
    cd "${BUILD_DIR}"

    # Optionale zusaetzliche lb-Argumente (ENV: LB_EXTRA_ARGS="--foo --bar")
    read -r -a LB_EXTRA <<< "${LB_EXTRA_ARGS:-}"

    lb config noauto \
        --distribution trixie \
        --architecture amd64 \
        --archive-areas "main contrib non-free non-free-firmware" \
        --mirror-bootstrap "https://deb.debian.org/debian" \
        --mirror-binary "https://deb.debian.org/debian" \
        --iso-volume "b3nsecu-${VERSION}" \
        --iso-application "b3nsecu Security Appliance" \
        --bootappend-live "boot=live components hostname=b3nsecu" \
        --debian-installer live \
        --image-name b3nsecu \
        --apt-recommends false \
        "${LB_EXTRA[@]}"

    # Externe Repos (Elastic, Wazuh, Zeek) fuer live-build einbinden
    # OHNE signed-by= - live-build installiert *.key.chroot automatisch als trusted keys
    mkdir -p config/archives
    cat > config/archives/elastic.list.chroot <<EOF
deb https://artifacts.elastic.co/packages/8.x/apt stable main
EOF
    cat > config/archives/wazuh.list.chroot <<EOF
deb https://packages.wazuh.com/4.x/apt/ stable main
EOF
    cat > config/archives/zeek-obs.list.chroot <<EOF
deb https://download.opensuse.org/repositories/security:/zeek/Debian_13/ /
EOF
    cat > config/archives/grafana.list.chroot <<EOF
deb https://apt.grafana.com stable main
EOF
    curl -fsSL https://apt.grafana.com/gpg.key \
        | gpg --batch --yes --dearmor -o config/archives/grafana.key.chroot
    cat > config/archives/backports.list.chroot <<EOF
deb http://deb.debian.org/debian trixie-backports main
EOF

    # GPG-Keys fuer die externen Repos herunterladen
    curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch \
        | gpg --batch --yes --dearmor -o config/archives/elastic.key.chroot
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --batch --yes --dearmor -o config/archives/wazuh.key.chroot
    curl -fsSL "https://download.opensuse.org/repositories/security:/zeek/Debian_13/Release.key" \
        | gpg --batch --yes --dearmor -o config/archives/zeek-obs.key.chroot

    # Keys ins Chroot kopieren (signed-by= zeigt auf /usr/share/keyrings/)
    mkdir -p config/includes.chroot/usr/share/keyrings
    cp config/archives/elastic.key.chroot  config/includes.chroot/usr/share/keyrings/elasticsearch-keyring.gpg
    cp config/archives/wazuh.key.chroot    config/includes.chroot/usr/share/keyrings/wazuh-keyring.gpg
    cp config/archives/zeek-obs.key.chroot config/includes.chroot/usr/share/keyrings/zeek-obs-keyring.gpg

    # Paketliste fuer das Live-Image
    mkdir -p config/package-lists config/hooks/live/
    cat > config/package-lists/b3nsecu.list.chroot <<EOF
linux-image-amd64
live-boot
systemd-sysv
sudo
openssh-client
nftables
suricata
zeek
wazuh-manager
grafana
prometheus
prometheus-node-exporter
EOF

    # Zusatzpakete je nach Profil
    if [[ "$PROFILE" == "full" || "$PROFILE" == "siem" ]]; then
        cat > config/package-lists/siem.list.chroot <<EOF
elasticsearch
logstash
kibana
EOF
    fi

    # Preseed fuer Unattended-Installation einbinden
    mkdir -p config/includes.installer/preseed
    if [[ -f "${SCRIPT_DIR}/preseed/b3nsecu-preseed.cfg" ]]; then
        cp "${SCRIPT_DIR}/preseed/b3nsecu-preseed.cfg" \
           config/includes.installer/preseed/
        log "Preseed eingebunden (Boot: auto=true file=/cdrom/preseed/b3nsecu-preseed.cfg)"
    fi

    # Konfigurationen ins Live-System uebernehmen
    mkdir -p config/includes.chroot/opt/b3nsecu
    cp -r "${SCRIPT_DIR}/config"/* config/includes.chroot/opt/b3nsecu/ 2>/dev/null || true
    cp "${SCRIPT_DIR}/install.sh" config/includes.chroot/opt/b3nsecu/ 2>/dev/null || true

    # WICHTIG: install.sh + config auch auf die ISO-Root (fuer den Installer!)
    # includes.binary landet direkt auf der ISO unter /b3nsecu/ - der
    # debian-installer kann sie dort per /cdrom/b3nsecu/ erreichen.
    mkdir -p config/includes.binary/b3nsecu
    cp -r "${SCRIPT_DIR}/config" config/includes.binary/b3nsecu/ 2>/dev/null || true
    cp "${SCRIPT_DIR}/install.sh" config/includes.binary/b3nsecu/ 2>/dev/null || true

    # Hook: User + Auto-Login (Fix fuer "Authentication failure" beim Boot)
    if [[ -f "${SCRIPT_DIR}/hooks-live/live-autologin.hook.chroot" ]]; then
        cp "${SCRIPT_DIR}/hooks-live/live-autologin.hook.chroot" \
           config/hooks/live/live-autologin.hook.chroot
        chmod +x config/hooks/live/live-autologin.hook.chroot
        log "Autologin-Fix-Hook eingebunden"
    fi

    # Hook: Dienste fuer das Live-System aktivieren
    cat > config/hooks/live/b3nsecu-postinst.hook.chroot <<'HOOK'
#!/bin/bash
set -e
echo "[b3nsecu] Aktiviere Dienste im Live-System..."
systemctl enable nftables suricata 2>/dev/null || true
systemctl enable prometheus prometheus-node-exporter 2>/dev/null || true
HOOK

    ok "live-build konfiguriert."
}

#-------------------------------------------------------------------------------
# ISO bauen
#-------------------------------------------------------------------------------
build_iso() {
    log "Starte ISO-Bau (kann 30-60 Min. dauern)..."
    cd "${BUILD_DIR}"
    lb build 2>&1 | tee "${SCRIPT_DIR}/build-$(date +%Y%m%d-%H%M%S).log"

    # live-build haengt Architektur+Typ an den Image-Namen (z.B. b3nsecu-amd64.hybrid.iso)
    local iso_file
    iso_file="$(find . -maxdepth 1 -name '*.iso' | head -1)"

    if [[ -n "$iso_file" ]]; then
        mkdir -p "${SCRIPT_DIR}/images"
        mv "$iso_file" "${SCRIPT_DIR}/images/b3nsecu-${VERSION}-amd64.iso"
        ok "ISO erfolgreich gebaut: images/b3nsecu-${VERSION}-amd64.iso"
    else
        die "ISO-Bau fehlgeschlagen. Pruefe build.log"
    fi
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --profile=*) PROFILE="${1#*=}" ;;
            *) die "Unbekanntes Argument: $1" ;;
        esac
        shift
    done
}

parse_args "$@"
check_prerequisites
configure_live_build
build_iso
