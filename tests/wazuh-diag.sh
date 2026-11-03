#!/usr/bin/env bash
#===============================================================================
# b3nsecu Wazuh-Diagnose: Daemons + Listening-Ports pruefen
#===============================================================================
echo "=== Wazuh-Daemon-Prozesse ==="
for pid in $(ls /proc | grep -E "^[0-9]+$"); do
  cmd=$(cat /proc/$pid/cmdline 2>/dev/null | tr "\0" " ")
  [[ "$cmd" == *wazuh* || "$cmd" == *ossec* ]] && echo "  PID $pid: $(echo "$cmd" | head -c 70)"
done

echo ""
echo "=== Listening-Ports ==="
# 55000 = API, 1514 = remoted, 1515 = authd (alle hex in /proc/net/tcp6)
for port_hex in D6B8 5EA 5EB; do
  if grep -qi ":$port_hex" /proc/net/tcp6 /proc/net/tcp 2>/dev/null; then
    case $port_hex in
      D6B8) echo "  Port 55000 (API)      : AKTIV" ;;
      5EA)  echo "  Port 1514 (remoted)  : AKTIV" ;;
      5EB)  echo "  Port 1515 (authd)    : AKTIV" ;;
    esac
  else
    case $port_hex in
      D6B8) echo "  Port 55000 (API)     : inaktiv" ;;
      5EA)  echo "  Port 1514 (remoted)  : inaktiv" ;;
      5EB)  echo "  Port 1515 (authd)    : inaktiv" ;;
    esac
  fi
done
