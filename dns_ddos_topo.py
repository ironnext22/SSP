#!/usr/bin/env python
# -*- coding: utf-8 -*-


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

        self.addLink(hC1, s1, bw=10, delay='2ms')
        self.addLink(hC2, s1, bw=10, delay='2ms')

        self.addLink(hA1, s2, bw=10, delay='2ms')
        self.addLink(hA2, s2, bw=10, delay='2ms')

        self.addLink(hDNS, s3, bw=20, delay='1ms')

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



def start_legit_dns_traffic(hC1, hC2):

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

    start_dns_server(hDNS)
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

