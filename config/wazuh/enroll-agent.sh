#!/usr/bin/env bash
#===============================================================================
# b3nsecu Wazuh-Agent Enrollment
# Registriert einen Debian-Agenten am b3nsecu Wazuh-Manager.
#
# Nutzung:
#   sudo ./enroll-agent.sh <MANAGER-IP> [GRUPPE]
#   sudo ./enroll-agent.sh 192.168.1.10 linux-agents
#===============================================================================
set -euo pipefail

log() { echo -e "\033[0;34m[INFO ]\033[0m $*"; }
ok()  { echo -e "\033[0;32m[ OK  ]\033[0m $*"; }
die() { echo -e "\033[0;31m[FEHLER]\033[0m $*" >&2; exit 1; }

MANAGER="${1:?Nutzung: $0 <MANAGER-IP> [GRUPPE]}"
GROUP="${2:-linux-agents}"

[[ $EUID -eq 0 ]] || die "Bitte als root ausfuehren"

#--- Wazuh-Repo einrichten ------------------------------------------------------
log "Richte Wazuh-Repository ein..."
if [[ ! -f /usr/share/keyrings/wazuh-keyring.gpg ]]; then
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --batch --yes --dearmor -o /usr/share/keyrings/wazuh-keyring.gpg
fi
echo "deb [signed-by=/usr/share/keyrings/wazuh-keyring.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list

apt-get update -qq
log "Installiere Wazuh-Agent..."
apt-get install -y -qq wazuh-agent

#--- Manager-Adresse setzen ----------------------------------------------------
log "Konfiguriere Manager: ${MANAGER}"
sed -i "s|<address>.*</address>|<address>${MANAGER}</address>|" /var/ossec/etc/ossec.conf

#--- Gruppe registrieren falls angegeben ---------------------------------------
if [[ -n "$GROUP" ]]; then
    sed -i "s|</server>|</server>\n  <group>${GROUP}</group>|" /var/ossec/etc/ossec.conf 2>/dev/null || true
fi

#--- Dienst starten (mit/ohne systemd) -------------------------------------------
if [[ -d /run/systemd/system ]]; then
    systemctl daemon-reload
    systemctl enable wazuh-agent
    systemctl restart wazuh-agent
else
    # Container/Umgebung ohne systemd: Wazuh-Control direkt nutzen
    /var/ossec/bin/wazuh-control start
fi

ok "Wazuh-Agent installiert und am Manager ${MANAGER} registriert."
log "Pruefe auf dem Manager: /var/ossec/bin/agent_control -l"
