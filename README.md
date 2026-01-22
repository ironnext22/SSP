# SSP

```mermaid
graph TD

    %% Przełączniki
    s0((s0 core))
    s1((s1 klienci))
    s2((s2 atakujący))
    s3((s3 DMZ))

    %% Hosty klienci
    hC1[hC1 10.0.0.11]
    hC2[hC2 10.0.0.12]

    %% Hosty atakujący
    hA1[hA1 10.0.0.21]
    hA2[hA2 10.0.0.22]

    %% Hosty DMZ
    hDNS[hDNS 10.0.0.53 DNS]

    %% Połączenia hostów z przełącznikami
    hC1 --- s1
    hC2 --- s1

    hA1 --- s2
    hA2 --- s2

    hDNS --- s3

    %% Połączenia między przełącznikami (core)
    s1 --- s0
    s2 --- s0
    s3 --- s0
```
```
```
DNS Flooding Detection in SDN (Floodlight + Mininet)
===================================================

This project demonstrates a DNS flooding detection algorithm implemented
as a Floodlight controller module and evaluated in a Mininet-based SDN testbed.

The goal is to show how DNS traffic volume and entropy can be monitored
to detect abnormal behavior such as DNS flooding attacks.


Project Structure
-----------------
- dnsdetect/
  - ```DNSFloodingDetector.java```     Floodlight module (detection logic)
- ```dns_ddos_topo.py```               Mininet topology and traffic generator
- ```attack_volume.sh```               DNS flood attack script (volume-based)
- ```attack_entropy.sh```              DNS flood attack script (entropy-based)
- ```stop_attacks.sh```                Script to stop all attack traffic
- ```README.txt / README.md```         Project documentation


Requirements
------------
System:
- Ubuntu 14.04 / 16.04 (recommended for Floodlight compatibility)

Software:
- Java 7 or 8
- Python 2.7
- Mininet
- Open vSwitch
- Floodlight Controller
- dig (dnsutils package)


Installation
------------
1. Install system dependencies:
   sudo apt update
   sudo apt install -y git openjdk-7-jdk python python-pip \
                       mininet openvswitch-switch \
                       dnsutils dnsmasq

2. Clone Floodlight:
   git clone https://github.com/floodlight/floodlight.git
   cd floodlight
   ant

3. Copy DNSFloodingDetector.java into:
   floodlight/src/main/java/net/floodlightcontroller/dnsdetect/

4. Register the module in:
   floodlight/src/main/resources/floodlightdefault.properties

5. Rebuild Floodlight:
   ant


Running the Experiment
----------------------
1. Start Floodlight:
   cd floodlight
   java -jar target/floodlight.jar

2. Start Mininet topology:
   sudo python dns_ddos_topo.py --controller-ip 127.0.0.1 --controller-port 6653

3. Basic DNS traffic starts automatically.
   Observe logs in Floodlight console:
   DNS WINDOW | domain=example.com volume=X pkt/s entropy=Y


Attack Scenarios
----------------
Volume-based DNS Flood:
- Generates a large number of DNS queries to the same domain.
- Run:
  bash attack_volume.sh <workers>

Entropy-based DNS Flood:
- Generates random subdomains to increase entropy.
- Run:
  bash attack_entropy.sh <workers>

Stop all attacks:
- Run:
  bash stop_attacks.sh

Detection Method (Volume + Entropy)
----------------------------------
The Floodlight module performs anomaly detection on DNS traffic using two
complementary indicators calculated per domain in fixed time windows.

### 1) Traffic Extraction (DNS UDP/53)
The detector analyzes only DNS queries transported over UDP:
- Ethernet type: IPv4
- IP protocol: UDP
- UDP destination port: 53

For each matching packet, the module parses the DNS payload and extracts:
- full queried name (QNAME), e.g. `a1b2c3.example.com`
- base domain, e.g. `example.com` (second-level + TLD)

The base domain is used as the aggregation key for statistics.

### 2) Time Windowing
Traffic is processed in constant windows:
- `WINDOW_MS = 1000 ms`

For each domain and each 1-second window the controller builds a list of
observed QNAME values (subdomains).

### 3) Metrics Computed Per Window
For every domain in a given window the module computes:

**A) Query Volume**
Number of DNS packets to the domain within the current window:
- `volume(domain) = number_of_dns_queries_in_window`

**B) Entropy of Subdomains**
To capture randomness typical for DNS flooding (randomized subdomains), Shannon
entropy is calculated over QNAME frequency distribution:

- Let `p_i` be the probability of QNAME i in the window.
- Shannon entropy:

`H(domain) = - Σ p_i log2(p_i)`

Interpretation:
- `H ≈ 0` → repeated queries to the same QNAME (no randomness)
- high `H` → many distinct subdomains, typical for entropy-based DNS flood

### 4) Baseline and Thresholding (Sliding History)
The detector maintains a sliding history (baseline) for each domain:
- `HISTORY_SIZE = 30` windows

From this history it computes:
- mean volume: `vMean`
- std volume: `vStd`
- mean entropy: `eMean`
- std entropy: `eStd`

Detection uses a simple statistical rule:

An attack is flagged if **either**:
- `volume > vMean + K * vStd`
- `entropy > eMean + K * eStd`

Where:
- `K = 3` (3-sigma threshold)

This approach allows:
- detecting classic volume floods (high packet rate)
- detecting entropy floods (random subdomains causing entropy spike)


Logs
----
Normal traffic:
DNS WINDOW | domain=example.com volume=4 pkt/s entropy=0.8

Detected attack:
DNS FLOOD DETECTED | domain=example.com volume=24 pkt/s entropy=0.65


Notes
-----
- Entropy may be 0 when all queries target the same subdomain.
- Legitimate traffic is intentionally low and stable.
- Attack traffic is generated externally to allow clear traffic spikes.
- Parameters such as window size, history length, and thresholds
  can be adjusted in DNSFloodingDetector.java.
