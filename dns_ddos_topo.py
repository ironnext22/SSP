#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Topologia do testów wykrywania ruchu DNS o wzorcach DDoS
Mininet + zewnętrzny kontroler (Floodlight / OpenDaylight / inny) jako RemoteController.

Uruchomienie:
    1. Floodlight:
        java -jar floodlight.jar

    2.  Uruchomienie topologi 
        sudo python dns_ddos_topo.py --controller-ip 127.0.0.1 --controller-port 6653

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
        self.addLink(hC1, s1, bw=10, delay='2ms')
        self.addLink(hC2, s1, bw=10, delay='2ms')

        # Atakujący
        self.addLink(hA1, s2, bw=10, delay='2ms')
        self.addLink(hA2, s2, bw=10, delay='2ms')

        # DMZ
        self.addLink(hDNS, s3, bw=20, delay='1ms')
        self.addLink(hWEB, s3, bw=20, delay='1ms')

        # --- Linki między przełącznikami ---
        # krawędzie -> core
        self.addLink(s1, s0, bw=100, delay='1ms')
        self.addLink(s2, s0, bw=100, delay='1ms')
        self.addLink(s3, s0, bw=100, delay='1ms')



def start_dns_server(hDNS):
    """
    Uruchamia prosty serwer DNS (dnsmasq) na hoście hDNS.
    Wymaga zainstalowanego dnsmasq w systemie.
    """
    # Na wszelki wypadek ubijamy stare instancje
    hDNS.cmd("pkill dnsmasq || true")

    # Minimalna konfiguracja w /tmp
    hDNS.cmd("echo 'listen-address=10.0.0.53' >> /tmp/dnsmasq.conf")
    hDNS.cmd("echo 'bind-interfaces' >> /tmp/dnsmasq.conf")
    hDNS.cmd("echo 'address=/example.com/10.0.0.80' >> /tmp/dnsmasq.conf")

    # Uruchomienie w tle
    hDNS.cmd(
        "dnsmasq --no-daemon "
        "--conf-file=/tmp/dnsmasq.conf "
        "--log-queries --log-facility=/tmp/dnsmasq.log &"
    )
    info("*** Serwer DNS (dnsmasq) uruchomiony na hDNS\n")


def start_legit_dns_traffic(hC1, hC2):
    """
    Generuje 'normalny' ruch DNS z hostów klienckich
    - okresowe zapytania dig do hDNS.
    """
    for h in (hC1, hC2):
        # Pętla w tle: co 1 s zapytanie o example.com
        h.cmd(
            "while true; do "
            "  dig @10.0.0.53 example.com +short >/dev/null 2>&1; "
            "  sleep 1; "
            "done &"
        )
    info("*** ruch DNS z hC1 i hC2 uruchomiony\n")


def start_dns_attack(hA1, hA2):
    """
    Generuje ruch 'atakujący' na port 53 hDNS.
    Przykład z użyciem hping3 (UDP flood).
    """
    # Ubijamy stare hpingi na wszelki wypadek
    hA1.cmd("pkill hping3 || true")
    hA2.cmd("pkill hping3 || true")

    # Flood UDP na port 53 (DNS)
    hA1.cmd("hping3 -2 10.0.0.53 -p 53 --flood >/tmp/hA1_hping.log 2>&1 &")
    hA2.cmd("hping3 -2 10.0.0.53 -p 53 --flood >/tmp/hA2_hping.log 2>&1 &")

    info("*** Atak DNS flood z hA1 i hA2 uruchomiony\n")

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
            "  curl -s http://10.0.0.80/ >/dev/null 2>&1; "
            "  sleep 2; "
            "done &"
        )
    info("*** Legitny ruch HTTP z hC1 i hC2 uruchomiony\n")

def start_iperf_background_traffic(hWEB, hC1, hC2, hA1=None, hA2=None):
    """
    Uruchamia ruch tła z użyciem iperfa:
    - na hWEB: serwer TCP (port 5001) i serwer UDP (port 5002),
    - na hC1/hC2: klienci TCP do hWEB,
    - opcjonalnie na hA1/hA2: klienci UDP do hWEB.

    Wymaga zainstalowanego 'iperf' w systemie hosta (VM z Mininetem).
    """

    # Na wszelki wypadek ubijamy stare iperfy na tych hostach
    for h in [hWEB, hC1, hC2, hA1, hA2]:
        if h is not None:
            h.cmd("pkill iperf || true")

    # --- Serwery na hWEB ---
    # Serwer TCP na porcie 5001
    hWEB.cmd("iperf -s -p 5001 >/tmp/iperf_tcp_server.log 2>&1 &")

    # Serwer UDP na porcie 5002
    hWEB.cmd("iperf -s -u -p 5002 >/tmp/iperf_udp_server.log 2>&1 &")

    # --- Klienci TCP (ruch 'normalny') z hC1 i hC2 ---
    # -t 300   -> 300 sekund (5 minut)
    # -i 10    -> raport co 10 sekund
    # &        -> w tle
    hC1.cmd("iperf -c {} -p 5001 -t 300 -i 10 >/tmp/iperf_hC1_tcp.log 2>&1 &"
            .format(hWEB.IP()))
    hC2.cmd("iperf -c {} -p 5001 -t 300 -i 10 >/tmp/iperf_hC2_tcp.log 2>&1 &"
            .format(hWEB.IP()))

    # --- Opcjonalni klienci UDP (dodatkowe obciążenie) z hA1 i hA2 ---
    # -u       -> UDP
    # -b 5M    -> 5 Mbit/s na klienta
    if hA1 is not None:
        hA1.cmd("iperf -c {} -u -p 5002 -b 5M -t 300 -i 10 "
                ">/tmp/iperf_hA1_udp.log 2>&1 &"
                .format(hWEB.IP()))
    if hA2 is not None:
        hA2.cmd("iperf -c {} -u -p 5002 -b 5M -t 300 -i 10 "
                ">/tmp/iperf_hA2_udp.log 2>&1 &"
                .format(hWEB.IP()))


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

     # Pobierz hosty
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
    start_dns_attack(hA1, hA2)

    #start_iperf_background_traffic(hWEB, hC1, hC2)

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

