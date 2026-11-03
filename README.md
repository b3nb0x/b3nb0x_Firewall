# b3nb0x Firewall – Security Appliance

Debian-13-basierter Security-Stack: NGFW + IDS/IPS + SIEM + EDR + Monitoring.

## 🚀 Schnellstart (curl to shell)

```bash
curl -fsSL https://raw.githubusercontent.com/b3nb0x/b3nb0x_Firewall/main/install.sh | bash
```

Das Script erkennt automatisch:
- **Root vs. Benutzer** (sudo-Fallback, curl|bash-kompatibel)
- **Netzwerk-Interfaces** (interaktive Auswahl mit IP-Anzeige)
- **Debian-Version** (getestet auf 13.7 / trixie)

## 📋 Profile

| Profil      | Inhalt                                             |
|-------------|----------------------------------------------------|
| `firewall`  | nftables + Suricata IPS + Zeek (Gateway/Router)    |
| `sensor`    | Nur IDS-Sensor, kein Routing (SPAN-Port)           |
| `siem`      | Elasticsearch + Logstash + Kibana                  |
| `edr`       | Wazuh Manager (FIM-Realtime aktiviert)             |
| `monitor`   | Prometheus + Grafana (mit provisioniertem Dashboard) |
| `full`      | Alles oben                                         |

## 🔧 Direkter Aufruf (non-interactive)

```bash
# Firewall-Gateway:
bash install.sh --profile=firewall --iface-wan=ens18 --iface-lan=ens19

# SIEM-Server:
bash install.sh --profile=siem

# EDR-Zentrale:
bash install.sh --profile=edr

# Ohne Security-Tools:
bash install.sh --profile=monitor --no-security
```

## 📦 Enthaltene Pakete

**Basis (immer):** curl, wget, git, vim, tmux, htop, ncdu, lsof, strace,
sysstat, tcpdump, nmap, mtr, traceroute, dnsutils, net-tools, ethtool,
jq, tree, rsync, chrony, unattended-upgrades

**Security (optional, `--no-security` zum Überspringen):**
fail2ban (SSH-Schutz vorkonfiguriert), clamav, yara, lynis, rkhunter

## 🌐 Ports & Dienste

| Layer     | Tool              | Port             |
|-----------|-------------------|------------------|
| Firewall  | nftables          | –                |
| IDS/IPS   | Suricata 7.x      | – (af-packet)    |
| NTA       | Zeek              | –                |
| SIEM      | Elasticsearch 8.x | 9200 (localhost) |
| Dashboards| Kibana            | 5601 (localhost) |
| EDR       | Wazuh Manager     | 55000            |
| Metrics   | Prometheus        | 9090             |
| Visuals   | Grafana           | 3000             |

## 🔑 Wazuh-Agent anbinden (Client)

```bash
sudo ./config/wazuh/enroll-agent.sh <MANAGER-IP> [GRUPPE]
```

## 🏗️ Eigene Distro bauen (optional)

```bash
sudo apt install live-build debootstrap git
sudo ./build-distro.sh
# → images/b3nsecu-1.0.0-amd64.iso
```

**Hinweis:** Der curl|bash-Weg ist der empfohlene Standard. Der Distro-Bau
ist für Offline-Appliances (Preseed in initrd, siehe build-final.log-Tests).

## 🧪 Getestet

- Debian 13.7 (trixie) – alle Profile
- Benutzer-Modus mit sudo + Root-Modus
- QEMU + Docker-Container
- Wazuh Manager ↔ Agent Enrollment (End-to-End, Regel 554)
