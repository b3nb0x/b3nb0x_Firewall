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

B3N_VERSION="2.0.0"
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
# Konfiguration (per ENV oder interaktiv ueberschreibbar)
#===============================================================================
PROFILE=""
IFACE_WAN=""
IFACE_LAN=""
INSTALL_SECURITY_TOOLS="yes"

#===============================================================================
# System-Erkennung
#===============================================================================
check_system() {
    [[ -f /etc/debian_version ]] || die "Kein Debian-basiertes System erkannt."
    command -v apt-get >/dev/null 2>&1 || die "apt-get nicht gefunden."

    local ver
    ver="$(cat /etc/debian_version)"
    log "System: Debian $(lsb_release -ds 2>/dev/null || echo "$ver")"

    # Architektur
    local arch
    arch="$(dpkg --print-architecture)"
    log "Architektur: ${arch}"
}

detect_interfaces() {
    log "Erkenne Netzwerk-Interfaces..."
    mapfile -t IFACES < <(ip -o link show | awk -F': ' '{print $2}' | grep -vE "^(lo|docker0|veth|br-)" | sort)

    if [[ ${#IFACES[@]} -eq 0 ]]; then
        die "Keine Netzwerk-Interfaces gefunden!"
    fi

    echo ""
    echo -e "${C_CYAN}Verfuegbare Interfaces:${C_OFF}"
    local i=1
    for iface in "${IFACES[@]}"; do
        local ip_addr
        ip_addr="$(ip -4 addr show "$iface" 2>/dev/null | grep -oE 'inet [0-9.]+' | awk '{print $2}' || echo "keine IP")"
        echo "  [$i] $iface  ($ip_addr)"
        ((i++))
    done
    echo ""
}

choose_interfaces() {
    detect_interfaces

    if [[ ${#IFACES[@]} -eq 1 ]]; then
        IFACE_WAN="${IFACES[0]}"
        warn "Nur ein Interface gefunden: $IFACE_WAN (WAN = LAN = $IFACE_WAN)"
        IFACE_LAN="$IFACE_WAN"
        return
    fi

    local wan_idx lan_idx
    read -rp "WAN-Interface (Uplink) [1]: " wan_idx
    wan_idx="${wan_idx:-1}"
    IFACE_WAN="${IFACES[$((wan_idx-1))]}"

    read -rp "LAN-Interface (intern) [2]: " lan_idx
    lan_idx="${lan_idx:-2}"
    IFACE_LAN="${IFACES[$((lan_idx-1))]}"

    ok "WAN: $IFACE_WAN | LAN: $IFACE_LAN"
}

#===============================================================================
# Interaktives Menue
#===============================================================================
show_menu() {
    echo -e "${C_CYAN}"
    cat <<'BANNER'
    ____  _____            __
   | __ )| ____|          / _|  ___  ___ _ ____   _____ _ __
   |  _ \|  _|   _____   | |_  / __|/ _ \ '__\ \ / / _ \ '__|
   | |_) | |___ |_____|  |  _| \__ \  __/ |   \ V /  __/ |
   |____/|_____|         |_|   |___/\___|_|    \_/ \___|_|
              Security Appliance Installer
BANNER
    echo -e "${C_OFF}"
    echo "Verfuegbare Profile:"
    echo "  1) firewall   - NGFW: nftables + Suricata IPS + Zeek (Gateway)"
    echo "  2) sensor     - IDS-Sensor: Suricata + Zeek (SPAN-Port, kein Routing)"
    echo "  3) siem       - SIEM: Elasticsearch + Logstash + Kibana"
    echo "  4) edr        - EDR: Wazuh Manager"
    echo "  5) monitor    - Monitoring: Prometheus + Grafana"
    echo "  6) full       - ALLES (All-in-One-Appliance)"
    echo ""
    read -rp "Profil waehlen [1-6]: " choice

    case "$choice" in
        1) PROFILE="firewall" ;;
        2) PROFILE="sensor" ;;
        3) PROFILE="siem" ;;
        4) PROFILE="edr" ;;
        5) PROFILE="monitor" ;;
        6) PROFILE="full" ;;
        *) die "Ungueltige Auswahl: $choice" ;;
    esac

    echo ""
    read -rp "Security-Tools (fail2ban, clamav, yara, lynis)? [J/n]: " sectools
    [[ "${sectools,,}" == "n" ]] && INSTALL_SECURITY_TOOLS="no"
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

    # Elastic Stack 8.x
    if [[ "$PROFILE" == "siem" || "$PROFILE" == "full" ]]; then
        log "Fuege Elastic-Repository hinzu..."
        curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch \
            | $SUDO gpg --batch --yes --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" \
            | $SUDO tee /etc/apt/sources.list.d/elastic-8.x.list >/dev/null
    fi

    # Wazuh 4.x
    if [[ "$PROFILE" == "edr" || "$PROFILE" == "full" ]]; then
        log "Fuege Wazuh-Repository hinzu..."
        curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
            | $SUDO gpg --batch --yes --dearmor -o /usr/share/keyrings/wazuh-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/wazuh-keyring.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
            | $SUDO tee /etc/apt/sources.list.d/wazuh.list >/dev/null
    fi

    # Grafana
    if [[ "$PROFILE" == "monitor" || "$PROFILE" == "full" ]]; then
        log "Fuege Grafana-Repository hinzu..."
        $SUDO mkdir -p /etc/apt/keyrings
        curl -fsSL https://apt.grafana.com/gpg.key \
            | $SUDO gpg --batch --yes --dearmor -o /etc/apt/keyrings/grafana.gpg
        echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" \
            | $SUDO tee /etc/apt/sources.list.d/grafana.list >/dev/null
    fi

    # Zeek (OBS - nicht in Debian main)
    if [[ "$PROFILE" == "firewall" || "$PROFILE" == "sensor" || "$PROFILE" == "full" ]]; then
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
    echo -e "  Profil:  ${C_CYAN}${PROFILE}${C_OFF}"
    echo -e "  WAN:     ${C_CYAN}${IFACE_WAN}${C_OFF}  |  LAN: ${C_CYAN}${IFACE_LAN}${C_OFF}"
    echo ""
    echo -e "  Dienste:"
    case "$PROFILE" in
        firewall|sensor|full)
            echo -e "    - nftables   : aktiv (Regelsatz /etc/nftables.conf)"
            echo -e "    - Suricata   : IPS auf ${IFACE_WAN} (af-packet)"
            echo -e "    - Zeek       : NTA auf ${IFACE_WAN}"
            ;;
    esac
    case "$PROFILE" in
        siem|full)
            echo -e "    - Elasticsearch : http://localhost:9200"
            echo -e "    - Kibana        : http://localhost:5601"
            ;;
    esac
    case "$PROFILE" in
        edr|full)
            echo -e "    - Wazuh      : https://localhost:55000"
            ;;
    esac
    case "$PROFILE" in
        monitor|full)
            echo -e "    - Prometheus : http://localhost:9090"
            echo -e "    - Grafana    : http://localhost:3000 (admin/admin)"
            ;;
    esac
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
    # Interaktiv wenn: kein Argument UND TTY vorhanden
    if [[ $# -eq 0 ]] && [[ -t 0 ]]; then
        show_menu
        choose_interfaces
    elif [[ $# -eq 0 ]]; then
        die "Kein Profil angegeben und keine TTY - nutze: $0 --profile=<firewall|sensor|siem|edr|monitor|full>"
    else
        # CLI-Argumente
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --profile=*)    PROFILE="${1#*=}" ;;
                --iface-wan=*)  IFACE_WAN="${1#*=}" ;;
                --iface-lan=*)  IFACE_LAN="${1#*=}" ;;
                --no-security)  INSTALL_SECURITY_TOOLS="no" ;;
                --help|-h)
                    sed -n '2,20p' "$0" 2>/dev/null || grep -E "^#" "$0" | head -20
                    exit 0 ;;
                *) die "Unbekanntes Argument: $1" ;;
            esac
            shift
        done
        [[ -n "$PROFILE" ]] || die "Kein Profil angegeben."
        # Interfaces nur bei firewall/sensor/full noetig
        [[ "$PROFILE" == "firewall" || "$PROFILE" == "sensor" || "$PROFILE" == "full" ]] && {
            [[ -n "$IFACE_WAN" ]] || choose_interfaces
        }
    fi

    [[ -n "$PROFILE" ]] || die "Kein Profil angegeben."

    check_system
    setup_repos
    install_base
    [[ "$INSTALL_SECURITY_TOOLS" == "yes" ]] && install_security_tools

    case "$PROFILE" in
        firewall) task_firewall; task_harden ;;
        sensor)   task_firewall ;;
        siem)     task_siem ;;
        edr)      task_edr ;;
        monitor)  task_monitor ;;
        full)
            task_firewall
            task_siem
            task_edr
            task_monitor
            task_harden
            ;;
        *) die "Unbekanntes Profil: $PROFILE" ;;
    esac

    show_summary
}

main "$@"
