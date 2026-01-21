#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Topologia do testów wykrywania ruchu DNS o wzorcach DDoS
Mininet + zewnętrzny kontroler (Floodlight / OpenDaylight / inny) jako RemoteController.
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

import argparse


class DnsDdosTopo(Topo):
    """
    Topologia:
        - s0: core
        - s1: klienci (hC1, hC2)
        - s2: atakujący (hA1, hA2)
        - s3: DMZ (hDNS, hWEB)
    """

    def build(self):
        s0 = self.addSwitch('s0')
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        hC1 = self.addHost('hC1', ip='10.0.0.11/24')
        hC2 = self.addHost('hC2', ip='10.0.0.12/24')

        hA1 = self.addHost('hA1', ip='10.0.0.21/24')
        hA2 = self.addHost('hA2', ip='10.0.0.22/24')

        hDNS = self.addHost('hDNS', ip='10.0.0.53/24')
        hWEB = self.addHost('hWEB', ip='10.0.0.80/24')

        self.addLink(hC1, s1, bw=10, delay='2ms')
        self.addLink(hC2, s1, bw=10, delay='2ms')

        self.addLink(hA1, s2, bw=10, delay='2ms')
        self.addLink(hA2, s2, bw=10, delay='2ms')

        self.addLink(hDNS, s3, bw=20, delay='1ms')
        self.addLink(hWEB, s3, bw=20, delay='1ms')

        self.addLink(s1, s0, bw=100, delay='1ms')
        self.addLink(s2, s0, bw=100, delay='1ms')
        self.addLink(s3, s0, bw=100, delay='1ms')


def start_dns_server(hDNS):
    hDNS.cmd("pkill dnsmasq || true")
    hDNS.cmd("echo 'listen-address=10.0.0.53' > /tmp/dnsmasq.conf")
    hDNS.cmd("echo 'bind-interfaces' >> /tmp/dnsmasq.conf")
    hDNS.cmd("echo 'address=/example.com/10.0.0.80' >> /tmp/dnsmasq.conf")

    hDNS.cmd(
        "dnsmasq --no-daemon "
        "--conf-file=/tmp/dnsmasq.conf "
        "--log-queries --log-facility=/tmp/dnsmasq.log &"
    )
    info("*** Serwer DNS (dnsmasq) uruchomiony na hDNS\n")

def start_dns_attack(hA1, hA2, workers=128, sleep_s=0.0):
    """
    Szybszy DNS flood: wiele równoleg�~Bych p�~Ytli 'dig' na host.
    workers  - ile równoleg�~Bych generatorów na host (np. 8/16/32)
    sleep_s  - opcjonalna pauza mi�~Ydzy zapytaniami (0.0 = max)
    """
    for h in (hA1, hA2):
        h.cmd("pkill dig || true")
        h.cmd("pkill -f 'while true; do.*dig @10.0.0.53' || true")

        # Odpalamy wiele p�~Ytli w tle
        for i in range(workers):
            if sleep_s > 0.0:
                h.cmd(
                    "sh -c 'while true; do "
                    "name=$(cat /proc/sys/kernel/random/uuid | tr -d \"-\" | cut -c1-10); "
                    "dig @10.0.0.53 ${name}.example.com +tries=1 +timeout=1 >/dev/null 2>&1; "
                    "sleep %s; "
                    "done' &" % sleep_s
                )
            else:
                h.cmd(
                    "sh -c 'while true; do "
                    "name=$(cat /proc/sys/kernel/random/uuid | tr -d \"-\" | cut -c1-10); "
                    "dig @10.0.0.53 ${name}.example.com +tries=1 +timeout=1 >/dev/null 2>&1; "
                    "done' &"
                )


def start_legit_dns_traffic(hC1, hC2):
    """
    LEGIT DNS TRAFFIC – OD ZERA
    - losowy wolumen 4–8 pkt/s
    - losowy wybór domen
    - zmiany co sekundę
    """

    domains = "www.example.com api.example.com mail.example.com cdn.example.com"

    for h in (hC1, hC2):
        h.cmd("pkill dig >/dev/null 2>&1 || true")

        h.cmd(
            "sh -c '"
            "while true; do "
            "COUNT=$((4 + RANDOM % 5)); "   # 4–8
            "for i in $(seq 1 $COUNT); do "
            "D=$(echo " + domains + " | tr \" \" \"\\n\" | shuf -n 1); "
            "dig @10.0.0.53 $D +tries=1 +timeout=1 >/dev/null 2>&1; "
            "done; "
            "sleep 1; "
            "done' &"
        )



def start_http_server(hWEB):
    hWEB.cmd("pkill -f 'python.*-m http\\.server 80' || true")
    hWEB.cmd("pkill -f 'python.*-m SimpleHTTPServer 80' || true")
    hWEB.cmd("cd /tmp && nohup python3 -m http.server 80 "
             ">/tmp/http.log 2>&1 </dev/null &")
    info("*** Prosty serwer HTTP na hWEB (port 80) uruchomiony\n")


def start_http_clients(hC1, hC2):
    for h in (hC1, hC2):
        h.cmd(
            "while true; do "
            "curl -s http://10.0.0.80/ >/dev/null 2>&1; "
            "sleep 2; "
            "done &"
        )
    info("*** Legitny ruch HTTP z hC1 i hC2 uruchomiony\n")


def start_iperf_background_traffic(hWEB, hC1, hC2, hA1=None, hA2=None):
    for h in [hWEB, hC1, hC2, hA1, hA2]:
        if h is not None:
            h.cmd("pkill iperf || true")

    hWEB.cmd("iperf -s -p 5001 >/tmp/iperf_tcp_server.log 2>&1 &")
    hWEB.cmd("iperf -s -u -p 5002 >/tmp/iperf_udp_server.log 2>&1 &")

    hC1.cmd("iperf -c {} -p 5001 -t 300 -i 10 >/tmp/iperf_hC1_tcp.log 2>&1 &"
            .format(hWEB.IP()))
    hC2.cmd("iperf -c {} -p 5001 -t 300 -i 10 >/tmp/iperf_hC2_tcp.log 2>&1 &"
            .format(hWEB.IP()))

    if hA1 is not None:
        hA1.cmd("iperf -c {} -u -p 5002 -b 5M -t 300 -i 10 "
                ">/tmp/iperf_hA1_udp.log 2>&1 &"
                .format(hWEB.IP()))
    if hA2 is not None:
        hA2.cmd("iperf -c {} -u -p 5002 -b 5M -t 300 -i 10 "
                ">/tmp/iperf_hA2_udp.log 2>&1 &"
                .format(hWEB.IP()))


def start_network(controller_ip, controller_port):

    topo = DnsDdosTopo()

    net = Mininet(
        topo=topo,
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=True
    )

    net.addController(
        'c0',
        controller=RemoteController,
        ip=controller_ip,
        port=controller_port
    )

    net.start()

    hC1 = net.get('hC1')
    hC2 = net.get('hC2')
    hA1 = net.get('hA1')
    hA2 = net.get('hA2')
    hDNS = net.get('hDNS')
    hWEB = net.get('hWEB')

    start_dns_server(hDNS)
    start_legit_dns_traffic(hC1, hC2)
    start_http_server(hWEB)
    start_http_clients(hC1, hC2)

    start_legit_dns_traffic(hC1, hC2)


    CLI(net)
    net.stop()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Topologia Mininet do testów DDoS w ruchu DNS"
    )
    parser.add_argument(
        "--controller-ip",
        default="127.0.0.1"
    )
    parser.add_argument(
        "--controller-port",
        type=int,
        default=6653
    )
    return parser.parse_args()


if __name__ == "__main__":
    setLogLevel('info')
    args = parse_args()
    start_network(args.controller_ip, args.controller_port)

