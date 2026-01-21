package net.floodlightcontroller.dnsdetect;

import net.floodlightcontroller.core.*;
import net.floodlightcontroller.core.module.*;
import net.floodlightcontroller.packet.*;

import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.types.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class DNSFloodingDetector
        implements IFloodlightModule, IOFMessageListener {

    private static final Logger logger =
            LoggerFactory.getLogger(DNSFloodingDetector.class);

    private IFloodlightProviderService floodlightProvider;

    // ===== PARAMETRY (ZGODNE Z PDF) =====
    private static final int DNS_PORT = 53;
    private static final int WINDOW_MS = 1000;
    private static final int HISTORY_SIZE = 30;
    private static final double K = 3;

    // ===== HISTORIE =====
    private final Map<String, List<Integer>> volumeHistory =
            new ConcurrentHashMap<String, List<Integer>>();

    private final Map<String, List<Double>> entropyHistory =
            new ConcurrentHashMap<String, List<Double>>();

    // ===== BIEŻĄCE OKNO =====
    private final Map<String, List<String>> currentWindow =
            new ConcurrentHashMap<String, List<String>>();

    private long windowStart = System.currentTimeMillis();

    @Override
    public String getName() {
        return "dns-flooding-detector";
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return false;
    }

    @Override
    public synchronized Command receive(
            IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {

        if (msg.getType() != OFType.PACKET_IN)
            return Command.CONTINUE;

        Ethernet eth = IFloodlightProviderService.bcStore.get(
                cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

        if (eth == null || eth.getEtherType() != EthType.IPv4)
            return Command.CONTINUE;

        IPv4 ip = (IPv4) eth.getPayload();
        if (ip == null || ip.getProtocol() != IpProtocol.UDP)
            return Command.CONTINUE;

        UDP udp = (UDP) ip.getPayload();
        if (udp == null)
            return Command.CONTINUE;

        // === TYLKO DNS UDP/53 ===
        if (!TransportPort.of(DNS_PORT).equals(udp.getDestinationPort()))
            return Command.CONTINUE;

        // === OCHRONA PRZED DHCP / LLDP / INNYMI UDP ===
        if (!(udp.getPayload() instanceof Data))
            return Command.CONTINUE;

        Data data = (Data) udp.getPayload();
        byte[] dns = data.getData();

        if (dns == null || dns.length < 13)
            return Command.CONTINUE;

        String qname = extractQName(dns);
        if (qname == null)
            return Command.CONTINUE;

        String domain = extractBaseDomain(qname);

        List<String> list = currentWindow.get(domain);
        if (list == null) {
            list = new ArrayList<String>();
            currentWindow.put(domain, list);
        }
        list.add(qname);

        long now = System.currentTimeMillis();
        if (now - windowStart >= WINDOW_MS) {
            analyzeWindow();
            currentWindow.clear();
            windowStart = now;
        }

        return Command.CONTINUE;
    }

    // ===== ANALIZA OKNA (PDF) =====
    private void analyzeWindow() {

        for (String domain : currentWindow.keySet()) {

            List<String> subs = currentWindow.get(domain);
            int volume = subs.size();
            double entropy = calculateEntropy(subs);

            // === LOG WOLUMENU NA SEKUNDĘ ===
            logger.info(
                "DNS WINDOW | domain={} volume={} pkt/s entropy={}",
                new Object[]{ domain, volume, entropy }
            );

            addHistory(volumeHistory, domain, volume);
            addHistory(entropyHistory, domain, entropy);
            
            

            if (volumeHistory.get(domain).size() >= HISTORY_SIZE) {

                double vMean = meanInt(volumeHistory.get(domain));
                double vStd = stdInt(volumeHistory.get(domain), vMean);

                double eMean = meanDouble(entropyHistory.get(domain));
                double eStd = stdDouble(entropyHistory.get(domain), eMean);

                logger.info(
                	    "STATS | domain={} vMean={} vStd={} eMean={} eStd={}",
                	    new Object[]{
                	        domain,
                	        vMean,
                	        vStd,
                	        eMean,
                	        eStd
                	    }
                	);

                if (volume > vMean + K * vStd ||
                    entropy > eMean + K * eStd) {

                    logger.warn(
                        "DNS FLOOD DETECTED | domain={} volume={} pkt/s entropy={}",
                        new Object[]{ domain, volume, entropy }
                    );
                }
            }
        }
    }

    // ===== DNS PARSING =====
    private String extractQName(byte[] data) {
        try {
            int i = 12; // DNS header
            StringBuilder sb = new StringBuilder();

            while (i < data.length && data[i] != 0) {
                int len = data[i++] & 0xff;
                if (i + len > data.length)
                    return null;
                if (sb.length() > 0)
                    sb.append(".");
                sb.append(new String(data, i, len));
                i += len;
            }
            return sb.toString().toLowerCase();
        } catch (Exception e) {
            return null;
        }
    }

    private String extractBaseDomain(String q) {
        String[] p = q.split("\\.");
        if (p.length < 2)
            return q;
        return p[p.length - 2] + "." + p[p.length - 1];
    }

    private double calculateEntropy(List<String> list) {
        Map<String, Integer> freq = new HashMap<String, Integer>();

        for (String s : list) {
            Integer c = freq.get(s);
            freq.put(s, c == null ? 1 : c + 1);
        }

        double e = 0.0;
        int n = list.size();

        for (Integer c : freq.values()) {
            double p = (double) c / n;
            e -= p * (Math.log(p) / Math.log(2));
        }
        return e;
    }

    // ===== STATYSTYKA =====
    private void addHistory(Map map, String key, Object v) {
        List l = (List) map.get(key);
        if (l == null) {
            l = new ArrayList();
            map.put(key, l);
        }
        l.add(v);
        if (l.size() > HISTORY_SIZE)
            l.remove(0);
    }

    private double meanInt(List<Integer> l) {
        double s = 0;
        for (int v : l)
            s += v;
        return s / l.size();
    }

    private double stdInt(List<Integer> l, double m) {
        double s = 0;
        for (int v : l)
            s += Math.pow(v - m, 2);
        return Math.sqrt(s / l.size());
    }

    private double meanDouble(List<Double> l) {
        double s = 0;
        for (double v : l)
            s += v;
        return s / l.size();
    }

    private double stdDouble(List<Double> l, double m) {
        double s = 0;
        for (double v : l)
            s += Math.pow(v - m, 2);
        return Math.sqrt(s / l.size());
    }

    // ===== FLOODLIGHT =====
    @Override
    public void init(FloodlightModuleContext context)
            throws FloodlightModuleException {

        floodlightProvider =
                context.getServiceImpl(IFloodlightProviderService.class);
    }

    @Override
    public void startUp(FloodlightModuleContext context) {

        floodlightProvider.addOFMessageListener(
                OFType.PACKET_IN, this);

        logger.info("DNS Flooding Detector ACTIVE");
    }

    @Override
    public Collection<Class<? extends IFloodlightService>>
    getModuleDependencies() {

        Collection<Class<? extends IFloodlightService>> deps =
                new ArrayList<Class<? extends IFloodlightService>>();

        deps.add(IFloodlightProviderService.class);
        return deps;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>>
    getModuleServices() {
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>,
               IFloodlightService>
    getServiceImpls() {
        return null;
    }
}
