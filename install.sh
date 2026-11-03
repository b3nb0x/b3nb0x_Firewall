#!/usr/bin/env bash
#===============================================================================
#  b3nb0x Firewall - Debian 13 Universal Installer
#-------------------------------------------------------------------------------
#  Kompletter Security-Stack: NGFW + IDS/IPS + SIEM + EDR + Monitoring
#
#  curl-to-shell:
#    curl -fsSL https://raw.githubusercontent.com/b3nb0x/b3nb0x_Firewall/main/install.sh | bash
#
#  Lokal:
#    bash install.sh
#
#  Features:
#    - Root/Benutzer-Erkennung (sudo-Fallback, curl|bash-kompatibel)
#    - Interaktives Menue (Profil + Interfaces)
#    - Alle Konfigurationen inline (keine Repo-Abhaengigkeit)
#    - Erweiterte Paketauswahl (Diagnose, Security, Tools)
#===============================================================================
set -euo pipefail

B3N_VERSION="2.1.0"
C_RED='\033[0;31m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[1;33m'
C_BLUE='\033[0;34m'; C_CYAN='\033[0;36m'; C_OFF='\033[0m'

log()  { echo -e "${C_BLUE}[INFO ]${C_OFF} $*"; }
ok()   { echo -e "${C_GREEN}[ OK  ]${C_OFF} $*"; }
warn() { echo -e "${C_YELLOW}[WARN ]${C_OFF} $*"; }
die()  { echo -e "${C_RED}[FEHLER]${C_OFF} $*" >&2; exit 1; }

#===============================================================================
# Root/Benutzer-Erkennung (curl|bash-kompatibel: kein exec-self-trick)
#===============================================================================
SUDO=""
if [[ $EUID -eq 0 ]]; then
    log "Laeufe als root."
else
    if command -v sudo >/dev/null 2>&1; then
        log "Laeufe als Benutzer - nutze sudo fuer privilegierte Befehle."
        SUDO="sudo"
    else
        die "Weder root noch sudo verfuegbar. Bitte als root oder mit sudo starten."
    fi
fi

#===============================================================================
# Konfiguration
#===============================================================================
SELECTED=()          # gewaehlte Komponenten (Array, Mehrfachauswahl!)
IFACE_WAN=""
IFACE_LAN=""
INSTALL_SECURITY_TOOLS="yes"

#===============================================================================
# whiptail verfuegbar? (TUI-Menue) - ggf. nachinstallieren
#===============================================================================
ensure_whiptail() {
    if command -v whiptail >/dev/null 2>&1; then
        return 0
    fi
    if [[ -t 0 ]]; then
        log "Installiere whiptail (TUI-Menue)..."
        $SUDO apt-get install -y -qq whiptail >/dev/null 2>&1 && return 0
    fi
    return 1
}

#===============================================================================
# Komponenten-Auswahl (TUI-Checklist: Leertaste = markieren!)
#===============================================================================
select_profiles() {
    if ensure_whiptail && [[ -t 0 ]]; then
        local result
        result=$(whiptail --title "b3nsecu Security Installer v${B3N_VERSION}" \
            --checklist \
"Komponenten waehlen:\n\n  [Leertaste] = markieren\n  [Enter] = bestaetigen\n\nMehrfachauswahl moeglich!" \
            22 78 10 \
            "firewall" "NGFW: nftables + Suricata IPS + Zeek (Gateway)" OFF \
            "sensor"   "IDS-Sensor: Suricata + Zeek (SPAN-Port)" OFF \
            "siem"     "SIEM: Elasticsearch + Logstash + Kibana" OFF \
            "edr"      "EDR: Wazuh Manager (FIM-Realtime)" OFF \
            "monitor"  "Monitoring: Prometheus + Grafana" OFF \
            3>&1 1>&2 2>&3) || die "Abgebrochen."

        # whiptail liefert: "firewall" "siem" (mit Quotes) -> Array parsen
        mapfile -t SELECTED < <(echo "$result" | tr -d '"' | tr ' ' '\n' | grep -v '^$')

        [[ ${#SELECTED[@]} -gt 0 ]] || die "Keine Komponente gewaehlt!"

        # Security-Tools-Frage
        if whiptail --title "Security-Tools" --yesno \
            "Zusaetzliche Security-Tools installieren?\n\n- fail2ban (SSH-Schutz vorkonfiguriert)\n- ClamAV (Virenscanner)\n- YARA (Rule-Engine)\n- Lynis + rkhunter (Audit)" \
            14 60; then
            INSTALL_SECURITY_TOOLS="yes"
        else
            INSTALL_SECURITY_TOOLS="no"
        fi
    else
        # Text-Fallback (kein whiptail / kein TTY)
        echo ""
        echo "Verfuegbare Komponenten (Nummern durch Leerzeichen getrennt):"
        echo "  1) firewall   - NGFW: nftables + Suricata IPS + Zeek"
        echo "  2) sensor     - IDS-Sensor (SPAN)"
        echo "  3) siem       - Elasticsearch + Logstash + Kibana"
        echo "  4) edr        - Wazuh Manager"
        echo "  5) monitor    - Prometheus + Grafana"
        read -rp "Auswahl [z.B. 1 3 5]: " choice
        for n in $choice; do
            case "$n" in
                1) SELECTED+=("firewall") ;;
                2) SELECTED+=("sensor") ;;
                3) SELECTED+=("siem") ;;
                4) SELECTED+=("edr") ;;
                5) SELECTED+=("monitor") ;;
                *) die "Ungueltige Nummer: $n" ;;
            esac
        done
        [[ ${#SELECTED[@]} -gt 0 ]] || die "Keine Komponente gewaehlt!"
        read -rp "Security-Tools installieren? [J/n]: " s
        [[ "${s,,}" == "n" ]] && INSTALL_SECURITY_TOOLS="no"
    fi

    log "Gewaehlt: ${SELECTED[*]}"
}

#===============================================================================
# Interface-Auswahl (nur bei firewall/sensor)
#===============================================================================
select_interfaces() {
    # Nur noetig wenn firewall oder sensor gewaehlt
    local needs_iface="no"
    for t in "${SELECTED[@]}"; do
        [[ "$t" == "firewall" || "$t" == "sensor" ]] && needs_iface="yes"
    done
    [[ "$needs_iface" == "yes" ]] || return 0

    mapfile -t IFACES < <(ip -o link show | awk -F': ' '{print $2}' | grep -vE "^(lo|docker0|veth|br-)" | sort)
    [[ ${#IFACES[@]} -gt 0 ]] || die "Keine Netzwerk-Interfaces gefunden!"

    # Das Interface mit der Default-Route ist der wahrscheinlichste Uplink
    local default_iface
    default_iface="$(detect_primary_iface)"
    [[ -n "$default_iface" ]] && log "Default-Route erkannt: $default_iface (als WAN vorausgewaehlt)"

    # whiptail-Liste mit IP-Anzeige bauen
    local entries=()
    for iface in "${IFACES[@]}"; do
        local ip_addr state="OFF"
        [[ "$iface" == "$default_iface" ]] && state="ON"
        ip_addr="$(ip -4 addr show "$iface" 2>/dev/null | grep -oE 'inet [0-9.]+' | awk '{print $2}' || echo "keine IP")"
        entries+=("$iface" "$ip_addr" "$state")
    done

    if ensure_whiptail && [[ -t 0 ]]; then
        # WAN (Radiolist - nur eine Auswahl)
        local wan_result
        wan_result=$(whiptail --title "WAN-Interface" --radiolist \
            "WAN-Interface (Uplink) waehlen:" 15 60 "${#IFACES[@]}" \
            "${entries[@]/OFF/ON}" 3>&1 1>&2 2>&3) || die "Abgebrochen."
        IFACE_WAN="$(echo "$wan_result" | tr -d '"')"

        # LAN (Menu)
        local lan_result
        lan_result=$(whiptail --title "LAN-Interface" --menu \
            "LAN-Interface (internes Netz) waehlen:" 15 60 "${#IFACES[@]}" \
            "${entries[@]}" 3>&1 1>&2 2>&3) || die "Abgebrochen."
        IFACE_LAN="$(echo "$lan_result" | tr -d '"')"
    else
        # Text-Fallback
        echo ""
        echo "Verfuegbare Interfaces:"
        local i=1
        for iface in "${IFACES[@]}"; do
            local ip_addr
            ip_addr="$(ip -4 addr show "$iface" 2>/dev/null | grep -oE 'inet [0-9.]+' | awk '{print $2}' || echo "keine IP")"
            echo "  [$i] $iface ($ip_addr)"
            ((i++))
        done
        read -rp "WAN [1]: " w; w="${w:-1}"
        IFACE_WAN="${IFACES[$((w-1))]}"
        read -rp "LAN [1]: " l; l="${l:-1}"
        IFACE_LAN="${IFACES[$((l-1))]}"
    fi

    ok "WAN: $IFACE_WAN | LAN: $IFACE_LAN"
}

#===============================================================================
# System-Erkennung
#===============================================================================
check_system() {
    [[ -f /etc/debian_version ]] || die "Kein Debian-basiertes System erkannt."
    command -v apt-get >/dev/null 2>&1 || die "apt-get nicht gefunden."

    local ver
    ver="$(cat /etc/debian_version)"
    log "System: Debian $(lsb_release -ds 2>/dev/null || echo "$ver")"

    local arch
    arch="$(dpkg --print-architecture)"
    log "Architektur: ${arch}"
}

detect_primary_iface() {
    ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'
}

#===============================================================================
# APT-Repositorien
#===============================================================================
setup_repos() {
    export DEBIAN_FRONTEND=noninteractive

    log "Aktualisiere Paketquellen..."
    $SUDO apt-get update -qq

    # apt-transport-https ist seit Debian 11 in apt integriert (obsolet, aber harmlos)
    $SUDO apt-get install -y -qq ca-certificates curl gnupg lsb-release apt-transport-https

    has_component() { printf '%s\n' "${SELECTED[@]}" | grep -qx "$1"; }

    # Elastic Stack 8.x
    if has_component "siem"; then
        log "Fuege Elastic-Repository hinzu..."
        curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch \
            | $SUDO gpg --batch --yes --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" \
            | $SUDO tee /etc/apt/sources.list.d/elastic-8.x.list >/dev/null
    fi

    # Wazuh 4.x
    if has_component "edr"; then
        log "Fuege Wazuh-Repository hinzu..."
        curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
            | $SUDO gpg --batch --yes --dearmor -o /usr/share/keyrings/wazuh-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/wazuh-keyring.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
            | $SUDO tee /etc/apt/sources.list.d/wazuh.list >/dev/null
    fi

    # Grafana
    if has_component "monitor"; then
        log "Fuege Grafana-Repository hinzu..."
        $SUDO mkdir -p /etc/apt/keyrings
        curl -fsSL https://apt.grafana.com/gpg.key \
            | $SUDO gpg --batch --yes --dearmor -o /etc/apt/keyrings/grafana.gpg
        echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" \
            | $SUDO tee /etc/apt/sources.list.d/grafana.list >/dev/null
    fi

    # Zeek (OBS - nicht in Debian main)
    if has_component "firewall" || has_component "sensor"; then
        log "Fuege Zeek-OBS-Repository hinzu..."
        curl -fsSL "https://download.opensuse.org/repositories/security:/zeek/Debian_13/Release.key" \
            | $SUDO gpg --batch --yes --dearmor -o /usr/share/keyrings/zeek-obs-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/zeek-obs-keyring.gpg] https://download.opensuse.org/repositories/security:/zeek/Debian_13/ /" \
            | $SUDO tee /etc/apt/sources.list.d/zeek-obs.list >/dev/null
    fi

    $SUDO apt-get update -qq
    ok "Repositorien konfiguriert."
}

#===============================================================================
# Basis-Pakete (immer)
#===============================================================================
install_base() {
    log "Installiere Basis-Pakete..."
    $SUDO apt-get install -y -qq \
        curl wget git vim tmux rsync jq tree unzip \
        htop ncdu lsof strace sysstat \
        tcpdump nmap mtr traceroute dnsutils net-tools ethtool \
        chrony unattended-upgrades
    ok "Basis-Pakete installiert."
}

#===============================================================================
# Security-Tools (optional, empfohlen)
#===============================================================================
install_security_tools() {
    log "Installiere Security-Tools (fail2ban, clamav, yara, lynis)..."
    $SUDO apt-get install -y -qq \
        fail2ban lynis rkhunter yara || warn "Einige Security-Tools fehlgeschlagen (optional)"

    # ClamAV (gross - nur wenn gewuenscht)
    $SUDO apt-get install -y -qq clamav clamav-daemon || warn "ClamAV fehlgeschlagen (optional)"

    # fail2ban Grundkonfiguration: SSH schuetzen
    if [[ -d /etc/fail2ban/jail.d ]]; then
        $SUDO tee /etc/fail2ban/jail.d/b3nsecu-ssh.local >/dev/null <<'EOF'
[b3nsecu-ssh]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
findtime = 600
EOF
        ok "fail2ban: SSH-Schutz aktiviert (5 Versuche, 1h Ban)"
    fi

    ok "Security-Tools installiert."
}

#===============================================================================
# Task: Firewall (nftables + Suricata IPS + Zeek)
#===============================================================================
task_firewall() {
    log "Installiere Firewall-Stack: nftables + Suricata + Zeek..."

    $SUDO apt-get install -y -qq nftables suricata zeek

    # --- nftables-Regelsatz (inline, keine externe Datei noetig) ---------------
    log "Konfiguriere nftables-Regelsatz..."
    $SUDO tee /etc/nftables.conf >/dev/null <<NFT
#!/usr/sbin/nft -f
# b3nsecu Firewall - nftables Grundregelsatz v${B3N_VERSION}
# WAN: ${IFACE_WAN} | LAN: ${IFACE_LAN}

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        iifname "lo" accept
        ct state established,related accept
        ct state invalid drop

        # SSH nur aus dem LAN (kein WAN-Zugriff)
        iifname != "${IFACE_WAN}" tcp dport 22 accept

        # Monitoring/Management nur aus dem LAN
        iifname != "${IFACE_WAN}" tcp dport { 9100, 9200, 5601, 3000, 55000 } accept

        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept

        limit rate 5/second log prefix "nft-drop-input: " level warning
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
        iifname "${IFACE_LAN}" oifname "${IFACE_WAN}" accept
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}

table ip nat {
    chain postrouting {
        type nat hook postrouting priority 100;
        oifname "${IFACE_WAN}" masquerade
    }
}
NFT

    # --- Suricata: Interface konfigurieren -------------------------------------
    log "Konfiguriere Suricata (Interface: ${IFACE_WAN})..."
    $SUDO mkdir -p /etc/systemd/system/suricata.service.d
    $SUDO tee /etc/systemd/system/suricata.service.d/override.conf >/dev/null <<EOF
[Service]
ExecStart=
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml --af-packet -i ${IFACE_WAN}
EOF

    # --- Zeek: Interface konfigurieren -----------------------------------------
    if [[ -f /opt/zeek/etc/node.cfg ]]; then
        log "Konfiguriere Zeek (Interface: ${IFACE_WAN})..."
        $SUDO sed -i "s/^interface=.*/interface=${IFACE_WAN}/" /opt/zeek/etc/node.cfg
    fi

    # --- systemd-Fallback (Container/Umgebungen ohne systemd) ------------------
    if [[ -d /run/systemd/system ]]; then
        $SUDO systemctl daemon-reload
        $SUDO systemctl enable nftables suricata 2>/dev/null || true
        $SUDO systemctl enable zeek 2>/dev/null || true
    else
        warn "systemd nicht aktiv - Dienste werden beim ersten Boot aktiviert."
    fi

    ok "Firewall-Stack installiert (WAN: ${IFACE_WAN}, LAN: ${IFACE_LAN})."
}

#===============================================================================
# Task: SIEM (Elasticsearch + Logstash + Kibana)
#===============================================================================
task_siem() {
    log "Installiere ELK-Stack 8.x (kann einige Minuten dauern)..."

    $SUDO apt-get install -y -qq elasticsearch logstash kibana

    # Elasticsearch: Single-Node, localhost-only
    log "Konfiguriere Elasticsearch..."
    $SUDO tee /etc/elasticsearch/elasticsearch.yml >/dev/null <<'EOF'
cluster.name: b3nsecu
node.name: node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 127.0.0.1
http.port: 9200
xpack.security.enabled: true
xpack.security.enrollment.enabled: true
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false
discovery.type: single-node
EOF

    # Kibana: localhost
    log "Konfiguriere Kibana..."
    $SUDO tee /etc/kibana/kibana.yml >/dev/null <<'EOF'
server.host: "127.0.0.1"
server.port: 5601
elasticsearch.hosts: ["http://127.0.0.1:9200"]
EOF

    # Logstash: Suricata EVE-JSON-Pipeline
    log "Konfiguriere Logstash-Pipeline (Suricata EVE-JSON)..."
    $SUDO tee /etc/logstash/conf.d/suricata.conf >/dev/null <<'EOF'
input {
  file {
    path => "/var/log/suricata/eve.json"
    start_position => "beginning"
    sincedb_path => "/var/lib/logstash/sincedb_suricata"
    codec => json
    type => "suricata"
  }
}

filter {
  if [type] == "suricata" {
    date {
      match => ["timestamp", "ISO8601"]
      target => "@timestamp"
    }
    geoip {
      source => "src_ip"
      target => "geoip"
    }
  }
}

output {
  elasticsearch {
    hosts => ["http://127.0.0.1:9200"]
    index => "suricata-%{+YYYY.MM.dd}"
  }
}
EOF

    # Dienste starten
    if [[ -d /run/systemd/system ]]; then
        $SUDO systemctl daemon-reload
        $SUDO systemctl enable elasticsearch logstash kibana
        log "Starte Elasticsearch (kann ~30s dauern)..."
        $SUDO systemctl start elasticsearch
        sleep 20
        $SUDO systemctl start logstash kibana
    else
        warn "systemd nicht aktiv - Dienste manuell starten."
    fi

    ok "ELK-Stack installiert: ES :9200, Kibana :5601, Logstash-Pipeline aktiv."
}

#===============================================================================
# Task: EDR (Wazuh Manager)
#===============================================================================
task_edr() {
    log "Installiere Wazuh Manager..."
    $SUDO apt-get install -y -qq wazuh-manager

    # FIM-Realtime-Monitoring aktivieren (Default ist nur 12h-Scan!)
    log "Aktiviere FIM-Realtime-Monitoring..."
    local conf="/var/ossec/etc/ossec.conf"
    if [[ -f "$conf" ]] && ! grep -q 'realtime="yes"' "$conf"; then
        $SUDO sed -i 's|<directories>|<directories check_all="yes" realtime="yes">|g' "$conf"
        ok "FIM-Realtime aktiviert (inotify)."
    fi

    if [[ -d /run/systemd/system ]]; then
        $SUDO systemctl enable wazuh-manager
        $SUDO systemctl restart wazuh-manager
    fi

    ok "Wazuh Manager installiert: API https://$(hostname -I | awk '{print $1}'):55000"
    warn "Wazuh-Admin-Passwort aendern: /var/ossec/api/configuration/auth"
}

#===============================================================================
# Task: Monitoring (Prometheus + Grafana)
#===============================================================================
task_monitor() {
    log "Installiere Prometheus + Grafana..."
    $SUDO apt-get install -y -qq prometheus prometheus-node-exporter grafana

    # Grafana-Provisioning: Datasources + Dashboards
    log "Konfiguriere Grafana-Provisioning..."
    $SUDO mkdir -p /etc/grafana/provisioning/datasources \
                 /etc/grafana/provisioning/dashboards \
                 /var/lib/grafana/dashboards

    $SUDO tee /etc/grafana/provisioning/datasources/b3nsecu.yml >/dev/null <<'EOF'
apiVersion: 1
datasources:
  - name: b3nsecu-elk
    uid: b3nsecu-elk
    type: elasticsearch
    access: proxy
    url: http://localhost:9200
    isDefault: true
    jsonData:
      index: suricata-*
      interval: Daily
      timeField: "@timestamp"
      esVersion: 8.0.0
      maxConcurrentShardRequests: 5
  - name: b3nsecu-prometheus
    uid: b3nsecu-prom
    type: prometheus
    access: proxy
    url: http://localhost:9090
    isDefault: false
    jsonData:
      timeInterval: 15s
EOF

    $SUDO tee /etc/grafana/provisioning/dashboards/b3nsecu.yml >/dev/null <<'EOF'
apiVersion: 1
providers:
  - name: b3nsecu
    orgId: 1
    folder: b3nsecu
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    options:
      path: /var/lib/grafana/dashboards
EOF

    # Suricata-Dashboard (kompakt, provisioniert)
    $SUDO tee /var/lib/grafana/dashboards/b3nsecu-suricata.json >/dev/null <<'EOF'
{
  "annotations": { "list": [] },
  "editable": true,
  "panels": [
    {
      "datasource": { "type": "elasticsearch", "uid": "b3nsecu-elk" },
      "gridPos": { "h": 4, "w": 8, "x": 0, "y": 0 },
      "id": 1,
      "options": { "colorMode": "value", "graphMode": "area", "reduceOptions": { "calcs": ["lastNotNull"] }, "textMode": "auto" },
      "targets": [{ "query": "event_type:alert", "refId": "A" }],
      "title": "Alerts (24h)",
      "type": "stat"
    },
    {
      "datasource": { "type": "elasticsearch", "uid": "b3nsecu-elk" },
      "gridPos": { "h": 4, "w": 8, "x": 8, "y": 0 },
      "id": 2,
      "options": { "colorMode": "value", "graphMode": "area", "reduceOptions": { "calcs": ["lastNotNull"] }, "textMode": "auto" },
      "targets": [{ "query": "event_type:dns", "refId": "A" }],
      "title": "DNS-Queries (24h)",
      "type": "stat"
    },
    {
      "datasource": { "type": "elasticsearch", "uid": "b3nsecu-elk" },
      "gridPos": { "h": 4, "w": 8, "x": 16, "y": 0 },
      "id": 3,
      "options": { "colorMode": "value", "graphMode": "area", "reduceOptions": { "calcs": ["lastNotNull"] }, "textMode": "auto" },
      "targets": [{ "query": "event_type:tls", "refId": "A" }],
      "title": "TLS-Handshakes (24h)",
      "type": "stat"
    }
  ],
  "refresh": "30s",
  "schemaVersion": 39,
  "tags": ["b3nsecu", "suricata"],
  "time": { "from": "now-24h", "to": "now" },
  "title": "b3nsecu - Suricata Overview",
  "uid": "b3nsecu-suricata",
  "version": 1
}
EOF

    $SUDO chown -R grafana:grafana /var/lib/grafana/dashboards

    if [[ -d /run/systemd/system ]]; then
        $SUDO systemctl enable prometheus prometheus-node-exporter grafana-server
        $SUDO systemctl restart prometheus grafana-server
    fi

    ok "Monitoring installiert: Prometheus :9090, Grafana :3000 (admin/admin)"
}

#===============================================================================
# Task: Haertung (SSH, Kernel, Sysctl)
#===============================================================================
task_harden() {
    log "Systemhaertung..."

    # SSH: Root-Login nur mit Key
    if [[ -f /etc/ssh/sshd_config ]]; then
        $SUDO sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
        $SUDO sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
        if [[ -d /run/systemd/system ]]; then
            $SUDO systemctl restart ssh 2>/dev/null || $SUDO systemctl restart sshd 2>/dev/null || true
        fi
    fi

    # Kernel-Sysctl fuer Gateway-Betrieb
    $SUDO tee /etc/sysctl.d/99-b3nsecu.conf >/dev/null <<'EOF'
# b3nsecu - Kernel-Haertung
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.log_martians = 1
EOF
    # sysctl braucht Kernel-Rechte (CAP_SYS_ADMIN) - in Containern ohne
    # privileged schlaegt es fehl; Haertung darf nicht fatal sein.
    $SUDO sysctl --system >/dev/null 2>&1 || warn "sysctl teilweise nicht anwendbar (Container ohne Kernel-Rechte)."
    ok "Haertung angewendet (IP-Forwarding, Anti-Spoofing, SYN-Cookies)."
}

#===============================================================================
# Zusammenfassung
#===============================================================================
show_summary() {
    echo ""
    echo -e "${C_GREEN}===============================================================${C_OFF}"
    echo -e "${C_GREEN}  b3nsecu Installation abgeschlossen (v${B3N_VERSION})${C_OFF}"
    echo -e "${C_GREEN}===============================================================${C_OFF}"
    echo ""
    echo -e "  Komponenten:  ${C_CYAN}${SELECTED[*]}${C_OFF}"
    echo -e "  WAN:     ${C_CYAN}${IFACE_WAN:-n/a}${C_OFF}  |  LAN: ${C_CYAN}${IFACE_LAN:-n/a}${C_OFF}"
    echo ""
    echo -e "  Dienste:"
    if printf '%s\n' "${SELECTED[@]}" | grep -qx "firewall"; then
        echo -e "    - nftables   : aktiv (Regelsatz /etc/nftables.conf)"
        echo -e "    - Suricata   : IPS auf ${IFACE_WAN} (af-packet)"
        echo -e "    - Zeek       : NTA auf ${IFACE_WAN}"
    fi
    if printf '%s\n' "${SELECTED[@]}" | grep -qx "sensor"; then
        echo -e "    - Suricata   : IDS auf ${IFACE_WAN} (Sensor-Modus)"
        echo -e "    - Zeek       : NTA auf ${IFACE_WAN}"
    fi
    if printf '%s\n' "${SELECTED[@]}" | grep -qx "siem"; then
        echo -e "    - Elasticsearch : http://localhost:9200"
        echo -e "    - Kibana        : http://localhost:5601"
    fi
    if printf '%s\n' "${SELECTED[@]}" | grep -qx "edr"; then
        echo -e "    - Wazuh      : https://localhost:55000"
    fi
    if printf '%s\n' "${SELECTED[@]}" | grep -qx "monitor"; then
        echo -e "    - Prometheus : http://localhost:9090"
        echo -e "    - Grafana    : http://localhost:3000 (admin/admin)"
    fi
    echo ""
    echo -e "  ${C_YELLOW}Naechste Schritte:${C_OFF}"
    echo -e "    1. Passwoerter aendern (Grafana: admin/admin, Wazuh-API)!"
    echo -e "    2. Wazuh-Agenten registrieren: config/wazuh/enroll-agent.sh"
    echo -e "    3. Dashboards in Grafana pruefen (b3nsecu-Folder)"
    echo ""
    echo -e "${C_GREEN}===============================================================${C_OFF}"
}

#===============================================================================
# Hauptprogramm
#===============================================================================
main() {
    # curl|bash-Fallstrick: stdin ist die PIPE (vom curl), kein Terminal!
    # Fuer den interaktiven Modus stdin vom Terminal (/dev/tty) umleiten.
    if [[ $# -eq 0 ]] && [[ ! -t 0 ]]; then
        if [[ -r /dev/tty ]]; then
            exec 0</dev/tty
            log "curl|bash erkannt - Interaktion ueber Terminal."
        else
            die "Kein TTY verfuegbar. Nutze: curl ... | bash -s -- --profile=<name>"
        fi
    fi

    # Interaktiv wenn: kein Argument (und jetzt TTY)
    if [[ $# -eq 0 ]]; then
        select_profiles
        select_interfaces
    else
        # CLI-Argumente
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --profile=*)    SELECTED+=("${1#*=}") ;;
                --iface-wan=*)  IFACE_WAN="${1#*=}" ;;
                --iface-lan=*)  IFACE_LAN="${1#*=}" ;;
                --no-security)  INSTALL_SECURITY_TOOLS="no" ;;
                --help|-h)
                    grep -E "^#" "$0" | head -22 | sed 's/^#//;s/^ //'
                    exit 0 ;;
                *) die "Unbekanntes Argument: $1" ;;
            esac
            shift
        done
        [[ ${#SELECTED[@]} -gt 0 ]] || die "Kein Profil angegeben."
    fi

    check_system
    setup_repos
    install_base
    [[ "$INSTALL_SECURITY_TOOLS" == "yes" ]] && install_security_tools

    # Alle gewaehlten Komponenten nacheinander installieren
    for task in "${SELECTED[@]}"; do
        case "$task" in
            firewall) task_firewall; task_harden ;;
            sensor)   task_firewall ;;
            siem)     task_siem ;;
            edr)      task_edr ;;
            monitor)  task_monitor ;;
            *) die "Unbekannte Komponente: $task" ;;
        esac
    done

    show_summary
}

main "$@"
