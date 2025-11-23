#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Topologia do testów wykrywania ruchu DNS o wzorcach DDoS
Mininet + zewnętrzny kontroler (Floodlight / OpenDaylight / inny) jako RemoteController.

Uruchomienie:
    1. Na VM / hoście z Floodlight:
        java -jar floodlight.jar

    2. Na VM z Mininetem (z tym skryptem):
        sudo python dns_ddos_topo.py --controller-ip 127.0.0.1 --controller-port 6653

    3. W konsoli Minineta (CLI) możesz np.:
        mininet> hC1 ping -c3 hDNS
        mininet> hA1 hping3 -2 10.0.0.53 -p 53 --flood &
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
        # --- Przełączniki ---
        s0 = self.addSwitch('s0')   # core
        s1 = self.addSwitch('s1')   # klienci
        s2 = self.addSwitch('s2')   # atakujący
        s3 = self.addSwitch('s3')   # DMZ

        # --- Hosty: klienci (legit) ---
        hC1 = self.addHost('hC1', ip='10.0.0.11/24')
        hC2 = self.addHost('hC2', ip='10.0.0.12/24')

        # --- Hosty: atakujący ---
        hA1 = self.addHost('hA1', ip='10.0.0.21/24')
        hA2 = self.addHost('hA2', ip='10.0.0.22/24')

        # --- Hosty: DMZ ---
        hDNS = self.addHost('hDNS', ip='10.0.0.53/24')
        hWEB = self.addHost('hWEB', ip='10.0.0.80/24')

        # --- Linki hostów (TCLink: można modyfikować bw/delay) ---
        # Klienci
        self.addLink(hC1, s1, bw=10, delay='2ms', use_htb=True)
        self.addLink(hC2, s1, bw=10, delay='2ms', use_htb=True)

        # Atakujący
        self.addLink(hA1, s2, bw=10, delay='2ms', use_htb=True)
        self.addLink(hA2, s2, bw=10, delay='2ms', use_htb=True)

        # DMZ
        self.addLink(hDNS, s3, bw=20, delay='1ms', use_htb=True)
        self.addLink(hWEB, s3, bw=20, delay='1ms', use_htb=True)

        # --- Linki między przełącznikami ---
        # krawędzie -> core
        self.addLink(s1, s0, bw=100, delay='1ms', use_htb=True)
        self.addLink(s2, s0, bw=100, delay='1ms', use_htb=True)
        self.addLink(s3, s0, bw=100, delay='1ms', use_htb=True)


def start_network(controller_ip, controller_port):
    """
    Startuje sieć Mininet z podaną topologią i łączy z kontrolerem
    (Floodlight / ODL / inny) jako RemoteController.
    """

    topo = DnsDdosTopo()

    net = Mininet(
        topo=topo,
        controller=None,           # kontroler dodamy ręcznie
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=True
    )

    info("*** Dodawanie kontrolera zdalnego (%s:%s)\n" %
         (controller_ip, controller_port))
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip=controller_ip,
        port=controller_port
    )

    info("*** Uruchamianie sieci\n")
    net.start()

    info("*** Hosty w sieci:\n")
    for host in net.hosts:
        info("  %s: IP=%s, MAC=%s\n" % (host.name, host.IP(), host.MAC()))

    info("\n*** Topologia uruchomiona.\n")
    info("*** Upewnij się, że kontroler widzi przełączniki s0-s3.\n")
    info("*** TODO: Generatory ruchu.\n\n")

    # Przykładowe komendy:
    info("Przykłady (wpisz w CLI Minineta):\n")
    info("  mininet> hC1 ping -c3 hDNS\n")
    info("  mininet> hC1 dig @10.0.0.53 example.com\n")
    info("  mininet> hA1 hping3 -2 10.0.0.53 -p 53 --flood &\n")
    info("  mininet> hA2 hping3 -2 10.0.0.53 -p 53 --flood &\n\n")

    # Wejście do interaktywnej konsoli
    CLI(net)

    info("*** Zatrzymywanie sieci\n")
    net.stop()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Topologia Mininet do testów DDoS w ruchu DNS (z kontrolerem zdalnym)."
    )
    parser.add_argument(
        "--controller-ip",
        dest="controller_ip",
        default="127.0.0.1",
        help="Adres IP hosta z kontrolerem (domyślnie 127.0.0.1)."
    )
    parser.add_argument(
        "--controller-port",
        dest="controller_port",
        type=int,
        default=6653,
        help="Port kontrolera OpenFlow (domyślnie 6653)."
    )
    return parser.parse_args()


if __name__ == "__main__":
    setLogLevel('info')
    args = parse_args()
    start_network(args.controller_ip, args.controller_port)

