package net.floodlightcontroller.dnsdetect;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.UDP;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.TableId;
import org.projectfloodlight.openflow.types.TransportPort;
import org.projectfloodlight.openflow.types.U64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class DNSFloodingDetector implements IFloodlightModule, IOFMessageListener {

    private static final Logger logger = LoggerFactory.getLogger(DNSFloodingDetector.class);

    private IFloodlightProviderService floodlightProvider;
    private IOFSwitchService switchService;

   
    private static final int DNS_PORT = 53;
    private static final int WINDOW_MS = 1000;
    private static final int HISTORY_SIZE = 30;
    private static final double K = 3;

   
    private static final int BAN_SECONDS = 30;            // 5 minut
    private static final int BAN_PRIORITY = 50000;         // wysoko
    private static final double OFFENDER_FRACTION = 0.20;  // 20% wolumenu domeny w oknie
    private static final int OFFENDER_MIN_PKTS = 20;       // albo min 20 pkt/okno


    private final Map<String, List<Integer>> volumeHistory =
            new ConcurrentHashMap<String, List<Integer>>();

    private final Map<String, List<Double>> entropyHistory =
            new ConcurrentHashMap<String, List<Double>>();


    private final Map<String, List<String>> currentWindow =
            new ConcurrentHashMap<String, List<String>>();

   
    private final Map<String, Map<IPv4Address, Integer>> currentWindowSrcCounts =
            new ConcurrentHashMap<String, Map<IPv4Address, Integer>>();

 
    private final Map<IPv4Address, Long> bannedIps =
            new ConcurrentHashMap<IPv4Address, Long>();

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
    public synchronized Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {

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

       
        if (!TransportPort.of(DNS_PORT).equals(udp.getDestinationPort()))
            return Command.CONTINUE;

        IPv4Address srcIp = ip.getSourceAddress();

        if (isBanned(srcIp)) {
            int remaining = remainingBanSeconds(srcIp);
            if (remaining > 0) {
                installDropRule(sw, srcIp, remaining);
            }
            return Command.STOP;
        }

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

      
        Map<IPv4Address, Integer> perSrc = currentWindowSrcCounts.get(domain);
        if (perSrc == null) {
            perSrc = new HashMap<IPv4Address, Integer>();
            currentWindowSrcCounts.put(domain, perSrc);
        }
        Integer c = perSrc.get(srcIp);
        perSrc.put(srcIp, (c == null) ? 1 : (c + 1));

        long now = System.currentTimeMillis();
        if (now - windowStart >= WINDOW_MS) {
            analyzeWindow();
            currentWindow.clear();
            currentWindowSrcCounts.clear();
            windowStart = now;
        }

        return Command.CONTINUE;
    }

   
    private void analyzeWindow() {

        for (String domain : currentWindow.keySet()) {

            List<String> subs = currentWindow.get(domain);
            if (subs == null || subs.isEmpty())
                continue;

            int volume = subs.size();
            double entropy = calculateEntropy(subs);

            logger.info("DNS WINDOW | domain={} volume={} pkt/s entropy={}",
                    new Object[]{domain, volume, entropy});

            addHistory(volumeHistory, domain, volume);
            addHistory(entropyHistory, domain, entropy);

            if (volumeHistory.get(domain).size() >= HISTORY_SIZE) {

                double vMean = meanInt(volumeHistory.get(domain));
                double vStd = stdInt(volumeHistory.get(domain), vMean);

                double eMean = meanDouble(entropyHistory.get(domain));
                double eStd = stdDouble(entropyHistory.get(domain), eMean);

                logger.info("STATS | domain={} vMean={} vStd={} eMean={} eStd={}",
                        new Object[]{domain, vMean, vStd, eMean, eStd});

                boolean flood =
                        (volume > vMean + K * vStd) ||
                        (entropy > eMean + K * eStd);

                if (flood) {
                    logger.warn("DNS FLOOD DETECTED | domain={} volume={} pkt/s entropy={}",
                            new Object[]{domain, volume, entropy});

                    Map<IPv4Address, Integer> perSrc = currentWindowSrcCounts.get(domain);
                    if (perSrc == null || perSrc.isEmpty())
                        continue;

                    int threshold = (int) Math.ceil(Math.max(OFFENDER_MIN_PKTS, OFFENDER_FRACTION * volume));

                    List<Map.Entry<IPv4Address, Integer>> entries =
                            new ArrayList<Map.Entry<IPv4Address, Integer>>(perSrc.entrySet());

                    Collections.sort(entries, new Comparator<Map.Entry<IPv4Address, Integer>>() {
                        @Override
                        public int compare(Map.Entry<IPv4Address, Integer> a, Map.Entry<IPv4Address, Integer> b) {
                            return b.getValue().compareTo(a.getValue());
                        }
                    });

                    int bannedCount = 0;
                    for (Map.Entry<IPv4Address, Integer> e : entries) {
                        IPv4Address src = e.getKey();
                        int cnt = e.getValue();
                        if (cnt >= threshold) {
                            banIpAcrossNetwork(src, BAN_SECONDS, domain, cnt, threshold, volume);
                            bannedCount++;
                        }
                    }

                    
                    if (bannedCount == 0 && !entries.isEmpty()) {
                        Map.Entry<IPv4Address, Integer> top = entries.get(0);
                        banIpAcrossNetwork(top.getKey(), BAN_SECONDS, domain, top.getValue(), threshold, volume);
                    }
                }
            }
        }
    }



    private boolean isBanned(IPv4Address ip) {
        Long until = bannedIps.get(ip);
        if (until == null) return false;
        long now = System.currentTimeMillis();
        if (now >= until) {
            bannedIps.remove(ip);
            return false;
        }
        return true;
    }

    private int remainingBanSeconds(IPv4Address ip) {
        Long until = bannedIps.get(ip);
        if (until == null) return 0;
        long now = System.currentTimeMillis();
        long diffMs = until - now;
        if (diffMs <= 0) return 0;
        return (int) Math.ceil(diffMs / 1000.0);
    }

    private void banIpAcrossNetwork(IPv4Address src, int seconds, String domain,
                                   int cntInWindow, int threshold, int windowVolume) {

        long until = System.currentTimeMillis() + (seconds * 1000L);

        Long existing = bannedIps.get(src);
        if (existing != null && existing > System.currentTimeMillis()) {
            if (until > existing) bannedIps.put(src, until);
        } else {
            bannedIps.put(src, until);
        }

        logger.warn("BANNING SRC IP | src={} ban={}s reason=DNS_FLOOD domain={} cntInWindow={} threshold={} windowVolume={}",
                new Object[]{src.toString(), seconds, domain, cntInWindow, threshold, windowVolume});

      
        Map<DatapathId, IOFSwitch> swMap = null;
        try {
            swMap = switchService.getAllSwitchMap();
        } catch (Exception ignored) {
          
        }

        if (swMap != null && !swMap.isEmpty()) {
            for (IOFSwitch sw : swMap.values()) {
                if (sw != null) installDropRule(sw, src, seconds);
            }
            return;
        }

      
        try {
            for (DatapathId dpid : switchService.getAllSwitchDpids()) {
                IOFSwitch sw = switchService.getSwitch(dpid);
                if (sw != null) installDropRule(sw, src, seconds);
            }
        } catch (Exception e) {
            logger.error("Cannot enumerate switches for banning: {}", e.toString());
        }
    }

    private void installDropRule(IOFSwitch sw, IPv4Address src, int hardTimeoutSec) {
        try {
            OFFactory f = sw.getOFFactory();
            OFVersion ver = f.getVersion();

            Match match = f.buildMatch()
                    .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                    .setExact(MatchField.IP_PROTO, IpProtocol.UDP)
                    .setExact(MatchField.IPV4_SRC, src)
                    .setExact(MatchField.UDP_DST, TransportPort.of(DNS_PORT))
                    .build();

        
            if (ver == OFVersion.OF_10 || ver == OFVersion.OF_11) {

                OFFlowMod fm = f.buildFlowAdd()
                        .setPriority(BAN_PRIORITY)
                        .setMatch(match)
                        .setHardTimeout(hardTimeoutSec)
                        .setIdleTimeout(0)
                        .setBufferId(OFBufferId.NO_BUFFER)
                        .setCookie(U64.of(0xD15EA5E))
                        .setActions(Collections.<OFAction>emptyList()) // DROP
                        .build();

                sw.write(fm);
                logger.info("Installed DNS drop-rule (OF1.0/1.1) | sw={} src={} hardTimeoutSec={}",
                        new Object[]{sw.getId().toString(), src.toString(), hardTimeoutSec});
                return;
            }

         
            OFFlowAdd fa = f.buildFlowAdd()
                    .setTableId(TableId.of(0))
                    .setPriority(BAN_PRIORITY)
                    .setMatch(match)
                    .setInstructions(Collections.<OFInstruction>emptyList()) // DROP
                    .setHardTimeout(hardTimeoutSec)
                    .setIdleTimeout(0)
                    .setBufferId(OFBufferId.NO_BUFFER)
                    .setCookie(U64.of(0xD15EA5E))
                    .build();

            sw.write(fa);
            logger.info("Installed DNS drop-rule (OF1.3+) | sw={} src={} hardTimeoutSec={}",
                    new Object[]{sw.getId().toString(), src.toString(), hardTimeoutSec});

        } catch (Exception e) {
            logger.error("Failed to install drop-rule | sw={} src={} err={}",
                    new Object[]{(sw != null ? sw.getId().toString() : "null"), src.toString(), e.toString()});
        }
    }

   
    private String extractQName(byte[] data) {
        try {
            int i = 12; 
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

  
    @SuppressWarnings({ "rawtypes", "unchecked" })
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
        for (int v : l) s += v;
        return s / l.size();
    }

    private double stdInt(List<Integer> l, double m) {
        double s = 0;
        for (int v : l) s += Math.pow(v - m, 2);
        return Math.sqrt(s / l.size());
    }

    private double meanDouble(List<Double> l) {
        double s = 0;
        for (double v : l) s += v;
        return s / l.size();
    }

    private double stdDouble(List<Double> l, double m) {
        double s = 0;
        for (double v : l) s += Math.pow(v - m, 2);
        return Math.sqrt(s / l.size());
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        switchService = context.getServiceImpl(IOFSwitchService.class);
    }

    @Override
    public void startUp(FloodlightModuleContext context) {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
        logger.info("DNS Flooding Detector ACTIVE (Floodlight v1.1, with banning)");
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> deps =
                new ArrayList<Class<? extends IFloodlightService>>();

        deps.add(IFloodlightProviderService.class);
        deps.add(IOFSwitchService.class);
        return deps;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return null;
    }
}
