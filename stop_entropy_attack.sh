#!/bin/bash

PIDFILE=/tmp/dns_entropy_attack.pid

if [ ! -f "$PIDFILE" ]; then
  echo "[!] No attack running"
  exit 0
fi

PID=$(cat "$PIDFILE")
kill $PID 2>/dev/null
rm -f "$PIDFILE"

pkill dig 2>/dev/null

echo "[*] Attack stopped"

