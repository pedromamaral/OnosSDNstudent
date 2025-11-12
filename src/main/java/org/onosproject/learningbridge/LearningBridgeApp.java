package org.onosproject.learningbridge;

import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TCP;
import org.onlab.packet.TpPort;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleEvent;
import org.onosproject.net.flow.FlowRuleListener;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flow.criteria.IPCriterion;
import org.onosproject.net.flow.criteria.TcpPortCriterion;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.TopologyService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ONOS Learning Bridge Application - Student Starter Template
 * 
 * LEARNING OBJECTIVES:
 * This application will teach you to implement a learning bridge with advanced features:
 * 1. Basic MAC address learning and forwarding
 * 2. Connection limiting (max simultaneous connections per host)
 * 3. TCP statistics logging (bytes, packets, duration)
 * 4. Flow rule management and lifecycle
 * 
 * TASKS TO COMPLETE:
 * - Implement packet processing logic
 * - Add MAC address learning
 * - Implement connection limiting
 * - Add flow rule installation
 * - Implement TCP connection tracking
 * - Add flow removal cleanup logic
 * 
 * See inline TODO comments for specific implementation points.
 */
@Component(immediate = true)
public class LearningBridgeApp {

    private final Logger log = LoggerFactory.getLogger(getClass());

    // ============================================================================
    // ONOS SERVICE REFERENCES
    // ============================================================================
    // These @Reference annotations inject ONOS services into your application
    // Think of them as APIs provided by ONOS for different functionalities

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;  // TODO: Used to register your application and get an ApplicationId

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;  // TODO: Handles packet-in/packet-out operations

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;  // TODO: Manages flow rules in switches

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;  // TODO: Higher-level API for flow management

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;  // TODO: Tracks discovered hosts in the network

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected TopologyService topologyService;  // TODO: Provides network topology information

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;  // TODO: Manages network devices (switches)

    // ============================================================================
    // APPLICATION STATE
    // ============================================================================
    
    private ApplicationId appId;  // Your application's unique identifier in ONOS
    private LearningBridgeProcessor processor = new LearningBridgeProcessor();
    private InternalFlowListener flowListener = new InternalFlowListener();

    // TODO: TASK 1 - Implement MAC Learning Table
    // HINT: Use a nested Map structure: DeviceId -> (MacAddress -> PortNumber)
    // This tracks which MAC addresses are reachable through which ports on each switch
    private Map<DeviceId, Map<MacAddress, PortNumber>> macTables = new ConcurrentHashMap<>();

    // TODO: TASK 2 - Implement Connection Tracking
    // HINT: Track active destinations per source host: SourceMac -> Set of DestMacs
    // This is used to enforce connection limits
    private Map<MacAddress, Set<MacAddress>> activeDestinations = new ConcurrentHashMap<>();

    // TODO: TASK 3 - Implement TCP Connection Tracking
    // HINT: Store TCP connection information using ConnectionKey -> TcpConnectionInfo
    // This tracks TCP connections for statistics logging
    private Map<ConnectionKey, TcpConnectionInfo> tcpConnections = new ConcurrentHashMap<>();

    // ============================================================================
    // CONFIGURATION CONSTANTS
    // ============================================================================
    // HINT: These values control application behavior - try changing them!
    
    // TODO: Experiment with different connection limits (try 1, 2, 5, 10)
    private static final int MAX_CONNECTIONS_PER_HOST = 2;

    // TODO: Flow timeout in seconds - how long should flows stay active?
    private static final int FLOW_TIMEOUT = 5;

    // TODO: Where should TCP connection statistics be logged?
    private static final String LOG_FILE_PATH = "/tmp/tcp_connections.log";

    // ============================================================================
    // APPLICATION LIFECYCLE
    // ============================================================================
    // ============================================================================
    // APPLICATION LIFECYCLE
    // ============================================================================

    /**
     * Called when the application is activated/started.
     * 
     * TODO: TASK 4 - Complete the activation logic
     * What needs to happen when your app starts?
     * 1. Register the application with ONOS
     * 2. Add the packet processor to handle incoming packets
     * 3. Add flow listener to monitor flow removals
     * 4. Request packet-in for all packets
     */
    @Activate
    protected void activate() {
        // TODO: Register this application with ONOS
        // HINT: Use coreService.registerApplication("org.onosproject.learningbridge")
        appId = coreService.registerApplication("org.onosproject.learningbridge");
        
        // TODO: Add packet processor to handle packet-in events
        // HINT: packetService.addProcessor(processor, PacketProcessor.director(2))
        packetService.addProcessor(processor, PacketProcessor.director(2));
        
        // TODO: Add flow listener to monitor flow rule events
        // HINT: flowRuleService.addListener(flowListener)
        flowRuleService.addListener(flowListener);

        // TODO: Request ONOS to send all packets to your application
        // HINT: Build an empty TrafficSelector and request packets with REACTIVE priority
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        log.info("Learning Bridge Application Started (Student Version) - Max connections: {}", 
                 MAX_CONNECTIONS_PER_HOST);
    }

    /**
     * Called when the application is deactivated/stopped.
     * 
     * TODO: TASK 5 - Complete the deactivation logic
     * What cleanup is needed when your app stops?
     * 1. Remove listeners
     * 2. Remove packet processor
     * 3. Remove all flow rules created by this app
     * 4. Log final statistics
     */
    @Deactivate
    protected void deactivate() {
        // TODO: Remove the flow listener
        // HINT: flowRuleService.removeListener(flowListener)
        flowRuleService.removeListener(flowListener);
        
        // TODO: Remove the packet processor
        // HINT: packetService.removeProcessor(processor)
        packetService.removeProcessor(processor);
        
        // TODO: Remove all flow rules installed by this application
        // HINT: flowRuleService.removeFlowRulesById(appId)
        flowRuleService.removeFlowRulesById(appId);

        // TODO: Log final TCP connection statistics before shutdown
        logAllConnectionStats();

        log.info("Learning Bridge Application Stopped");
    }

    // ============================================================================
    // PACKET PROCESSING
    // ============================================================================
    // ============================================================================
    // PACKET PROCESSING
    // ============================================================================

    /**
     * Packet processor that handles incoming packets.
     * This is the heart of your learning bridge application.
     */
    private class LearningBridgeProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            // TODO: TASK 6 - Check if packet is already handled
            // HINT: If context.isHandled() returns true, just return
            if (context.isHandled()) {
                return;
            }

            // TODO: TASK 7 - Extract packet information
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            // HINT: If packet can't be parsed, return early
            if (ethPkt == null) {
                return;
            }

            // TODO: TASK 8 - Extract MAC addresses and port information
            // HINT: Get source MAC, destination MAC, device ID, and input port from the packet
            MacAddress srcMac = ethPkt.getSourceMAC();
            MacAddress dstMac = ethPkt.getDestinationMAC();
            DeviceId deviceId = pkt.receivedFrom().deviceId();
            PortNumber inPort = pkt.receivedFrom().port();

            // TODO: TASK 9 - Implement MAC address learning
            // HINT: Store the mapping of srcMac -> inPort in the macTables for this deviceId
            // HINT: Use macTables.putIfAbsent() to create device entry if needed
            // HINT: Then update the MAC -> Port mapping
            macTables.putIfAbsent(deviceId, new ConcurrentHashMap<>());
            macTables.get(deviceId).put(srcMac, inPort);

            log.debug("Learned: {} -> port {} on device {}", srcMac, inPort, deviceId);

            // TODO: TASK 10 - Implement connection limiting
            // QUESTION: Why should we exclude broadcast and multicast traffic from connection limits?
            // ANSWER: _____________________________________________________________
            // 
            // HINT: Check if destination is NOT broadcast and NOT multicast
            // HINT: Track active destinations for the source MAC
            // HINT: If new destination and limit reached, block the packet
            if (!dstMac.isBroadcast() && !dstMac.isMulticast()) {
                // TODO: Get or create the set of active destinations for srcMac
                activeDestinations.putIfAbsent(srcMac, ConcurrentHashMap.newKeySet());
                Set<MacAddress> destinations = activeDestinations.get(srcMac);

                // TODO: Check if this is a new destination and limit is reached
                if (!destinations.contains(dstMac) && destinations.size() >= MAX_CONNECTIONS_PER_HOST) {
                    // TODO: Log warning and block the packet
                    log.warn("Connection limit reached for host {}. Dropping packet to new destination {}", 
                             srcMac, dstMac);
                    context.block();
                    return;
                }

                // TODO: Add this destination to the active set
                destinations.add(dstMac);
            }

            // TODO: TASK 11 - Handle TCP packets for statistics logging
            // HINT: Check if packet is IPv4 and TCP
            boolean isTcp = false;
            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
                if (ipv4Packet.getProtocol() == IPv4.PROTOCOL_TCP) {
                    isTcp = true;
                    // TODO: Call handleTcpTracking() method
                    handleTcpTracking(context, ethPkt, ipv4Packet);
                }
            }

            // TODO: TASK 12 - Implement forwarding decision
            // HINT: Look up the destination MAC in the MAC table for this device
            PortNumber outPort = macTables.get(deviceId).get(dstMac);

            if (outPort != null) {
                // TODO: Destination is known - install flow rule and forward
                installRule(context, outPort, isTcp);
            } else {
                // TODO: Destination unknown - flood the packet
                flood(context);
            }
        }

        /**
         * TODO: TASK 13 - Implement TCP connection tracking
         * 
         * This method tracks TCP connections for statistics logging.
         * HINT: Only track SYN packets (new connections)
         * HINT: Flow expiry will be handled by the FlowRuleListener
         */
        private void handleTcpTracking(PacketContext context, Ethernet ethPkt, IPv4 ipv4Packet) {
            // TODO: Extract TCP packet from IPv4 payload
            TCP tcpPacket = (TCP) ipv4Packet.getPayload();
            
            // TODO: Get MAC addresses from Ethernet header
            MacAddress srcMac = ethPkt.getSourceMAC();
            MacAddress dstMac = ethPkt.getDestinationMAC();
            DeviceId deviceId = context.inPacket().receivedFrom().deviceId();

            // TODO: Create a ConnectionKey to identify this TCP connection
            ConnectionKey connKey = new ConnectionKey(
                srcMac, dstMac,
                ipv4Packet.getSourceAddress(),
                ipv4Packet.getDestinationAddress(),
                tcpPacket.getSourcePort(),
                tcpPacket.getDestinationPort()
            );

            // TODO: Check for SYN flag (bit 1 in TCP flags = 0x02)
            // HINT: Use bitwise AND to check if SYN flag is set
            if ((tcpPacket.getFlags() & 0x02) != 0) {
                // TODO: If this is a new connection (not already tracked), create TcpConnectionInfo
                if (!tcpConnections.containsKey(connKey)) {
                    TcpConnectionInfo info = new TcpConnectionInfo(deviceId, srcMac, dstMac);
                    tcpConnections.put(connKey, info);
                    log.info("Tracking new TCP connection: {} -> {}:{}", 
                             srcMac, dstMac, tcpPacket.getDestinationPort());
                }
            }
            
            // NOTE: We don't track FIN/RST here - flow expiry is handled by InternalFlowListener
        }

        /**
         * TODO: TASK 14 - Implement flow rule installation
         * 
         * Installs a flow rule in the switch to handle future packets of this flow.
         * QUESTION: Why install flow rules instead of handling every packet?
         * ANSWER: _____________________________________________________________
         */
        private void installRule(PacketContext context, PortNumber portNumber, boolean isTcp) {
            // TODO: Get packet information
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            // TODO: Build traffic selector (what packets should match this rule?)
            TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();
            
            // TODO: Add basic matching criteria: input port, source MAC, destination MAC
            selectorBuilder.matchInPort(pkt.receivedFrom().port())
                          .matchEthSrc(ethPkt.getSourceMAC())
                          .matchEthDst(ethPkt.getDestinationMAC());
            
            // TODO: For TCP packets, add more specific matching
            // QUESTION: Why do we need more specific matching for TCP?
            // ANSWER: _____________________________________________________________
            if (isTcp) {
                IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
                TCP tcpPacket = (TCP) ipv4Packet.getPayload();
                
                // TODO: Add TCP-specific matching criteria
                selectorBuilder.matchEthType(Ethernet.TYPE_IPV4)
                              .matchIPProtocol(IPv4.PROTOCOL_TCP)
                              .matchIPSrc(Ip4Prefix.valueOf(Ip4Address.valueOf(ipv4Packet.getSourceAddress()), 32))
                              .matchIPDst(Ip4Prefix.valueOf(Ip4Address.valueOf(ipv4Packet.getDestinationAddress()), 32))
                              .matchTcpSrc(TpPort.tpPort(tcpPacket.getSourcePort()))
                              .matchTcpDst(TpPort.tpPort(tcpPacket.getDestinationPort()));
            }

            // TODO: Build traffic treatment (what action should be taken?)
            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .setOutput(portNumber)
                    .build();

            // TODO: Create forwarding objective
            // HINT: Higher priority for TCP flows (20 vs 10)
            // HINT: Make it temporary with FLOW_TIMEOUT
            ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                    .withSelector(selectorBuilder.build())
                    .withTreatment(treatment)
                    .withPriority(isTcp ? 20 : 10)
                    .withFlag(ForwardingObjective.Flag.VERSATILE)
                    .fromApp(appId)
                    .makeTemporary(FLOW_TIMEOUT)
                    .add();

            // TODO: Install the flow rule on the switch
            flowObjectiveService.forward(pkt.receivedFrom().deviceId(), forwardingObjective);

            // TODO: Forward this packet out the correct port
            context.treatmentBuilder().setOutput(portNumber);
            context.send();
        }

        /**
         * TODO: TASK 15 - Implement packet flooding
         * 
         * Floods the packet to all ports except the input port.
         * QUESTION: When do we need to flood packets?
         * ANSWER: _____________________________________________________________
         */
        private void flood(PacketContext context) {
            // TODO: Set output to FLOOD and send the packet
            context.treatmentBuilder().setOutput(PortNumber.FLOOD);
            context.send();
        }
    }

    // ============================================================================
    // FLOW RULE MANAGEMENT
    // ============================================================================
    // ============================================================================
    // FLOW RULE MANAGEMENT
    // ============================================================================

    /**
     * Listens for flow rule removal events (including timeouts).
     * When a flow is removed, this listener cleans up connection tracking.
     * 
     * TODO: TASK 16 - Understand flow lifecycle management
     * QUESTION: Why do we need to listen for flow removal events?
     * ANSWER: _____________________________________________________________
     */
    private class InternalFlowListener implements FlowRuleListener {
        
        @Override
        public void event(FlowRuleEvent event) {
            FlowRule flowRule = event.subject();

            // TODO: Only process removals of OUR flows
            // HINT: Check if flowRule.appId() matches our appId
            if (flowRule.appId() != appId.id()) {
                return;
            }

            // TODO: TASK 17 - Handle flow removal events
            // HINT: Check if event type is RULE_REMOVED
            if (event.type() == FlowRuleEvent.Type.RULE_REMOVED) {
                log.debug("Flow rule removed: {}", flowRule.id());
                
                // TODO: Clean up destination tracking for ALL flows
                handleFlowRemoval(flowRule);
                
                // TODO: Check if this was a TCP flow and log statistics
                handleTcpFlowRemoval(flowRule);
            }
        }

        /**
         * TODO: TASK 18 - Implement flow removal cleanup
         * 
         * Handles removal of ANY flow - cleans up destination tracking.
         * This ensures connection limits work correctly for all protocols.
         * 
         * QUESTION: Why is this cleanup important for connection limiting?
         * ANSWER: _____________________________________________________________
         */
        private void handleFlowRemoval(FlowRule flowRule) {
            TrafficSelector selector = flowRule.selector();

            try {
                // TODO: Extract MAC addresses from the flow rule selector
                // HINT: Use getCriterion(Criterion.Type.ETH_SRC) and ETH_DST
                EthCriterion srcEthCriterion = (EthCriterion) selector.getCriterion(Criterion.Type.ETH_SRC);
                EthCriterion dstEthCriterion = (EthCriterion) selector.getCriterion(Criterion.Type.ETH_DST);

                if (srcEthCriterion == null || dstEthCriterion == null) {
                    return; // Not a unicast flow
                }

                MacAddress srcMac = srcEthCriterion.mac();
                MacAddress dstMac = dstEthCriterion.mac();

                // TODO: Skip broadcast/multicast addresses
                if (dstMac.isBroadcast() || dstMac.isMulticast()) {
                    return;
                }

                // TODO: Check if there are any remaining active flows between these hosts
                // HINT: Use hasActiveFlowsBetween() method
                if (!hasActiveFlowsBetween(srcMac, dstMac)) {
                    // TODO: No more flows - remove destination from tracking
                    Set<MacAddress> destinations = activeDestinations.get(srcMac);
                    if (destinations != null) {
                        boolean removed = destinations.remove(dstMac);
                        if (removed) {
                            log.info("Connection ended: {} -> {}. Active destinations: {}", 
                                     srcMac, dstMac, destinations.size());
                        }
                    }
                }
            } catch (Exception e) {
                log.error("Error cleaning up flow removal", e);
            }
        }

        /**
         * TODO: TASK 19 - Implement active flow checking
         * 
         * Check if there are any active flows between source and destination MACs.
         * HINT: Query all devices and check their flow entries
         */
        private boolean hasActiveFlowsBetween(MacAddress srcMac, MacAddress dstMac) {
            // TODO: Iterate through all devices
            for (Device device : deviceService.getAvailableDevices()) {
                // TODO: Get flow entries for this device
                Iterable<FlowEntry> flowEntries = flowRuleService.getFlowEntries(device.id());
                
                for (FlowEntry entry : flowEntries) {
                    // TODO: Only check flows from our app
                    if (entry.appId() != appId.id()) {
                        continue;
                    }
                    
                    TrafficSelector selector = entry.selector();
                    
                    // TODO: Extract source and destination MAC from selector
                    EthCriterion srcEth = (EthCriterion) selector.getCriterion(Criterion.Type.ETH_SRC);
                    EthCriterion dstEth = (EthCriterion) selector.getCriterion(Criterion.Type.ETH_DST);
                    
                    // TODO: Check if this flow matches our source and destination
                    if (srcEth != null && dstEth != null &&
                        srcEth.mac().equals(srcMac) && dstEth.mac().equals(dstMac)) {
                        return true; // Found an active flow
                    }
                }
            }
            
            return false; // No active flows
        }

        /**
         * TODO: TASK 20 - Implement TCP flow removal handling
         * 
         * Handles removal of TCP flows - retrieves statistics and logs.
         */
        private void handleTcpFlowRemoval(FlowRule flowRule) {
            TrafficSelector selector = flowRule.selector();

            // TODO: Check if this is a TCP flow
            // HINT: Look for IP_PROTO criterion
            Criterion ipProtoCriterion = selector.getCriterion(Criterion.Type.IP_PROTO);
            if (ipProtoCriterion == null) {
                return; // Not a TCP flow
            }

            // TODO: Extract connection details from the flow rule
            try {
                // TODO: Get MAC addresses, IP addresses, and ports from the selector
                MacAddress srcMac = ((EthCriterion) selector.getCriterion(Criterion.Type.ETH_SRC)).mac();
                MacAddress dstMac = ((EthCriterion) selector.getCriterion(Criterion.Type.ETH_DST)).mac();
                
                IPCriterion srcIpCriterion = (IPCriterion) selector.getCriterion(Criterion.Type.IPV4_SRC);
                IPCriterion dstIpCriterion = (IPCriterion) selector.getCriterion(Criterion.Type.IPV4_DST);
                
                TcpPortCriterion srcPortCriterion = (TcpPortCriterion) selector.getCriterion(Criterion.Type.TCP_SRC);
                TcpPortCriterion dstPortCriterion = (TcpPortCriterion) selector.getCriterion(Criterion.Type.TCP_DST);

                if (srcIpCriterion == null || dstIpCriterion == null || 
                    srcPortCriterion == null || dstPortCriterion == null) {
                    return; // Not a complete TCP flow
                }

                // TODO: Convert IP addresses and ports to create ConnectionKey
                Ip4Address srcIp4 = srcIpCriterion.ip().address().getIp4Address();
                Ip4Address dstIp4 = dstIpCriterion.ip().address().getIp4Address();
                int srcIp = srcIp4.toInt();
                int dstIp = dstIp4.toInt();
                int srcPort = srcPortCriterion.tcpPort().toInt();
                int dstPort = dstPortCriterion.tcpPort().toInt();

                ConnectionKey connKey = new ConnectionKey(srcMac, dstMac, srcIp, dstIp, srcPort, dstPort);

                // TODO: Check if we were tracking this TCP connection
                TcpConnectionInfo info = tcpConnections.remove(connKey);
                if (info != null) {
                    // TODO: Set end time and get statistics from flow entry
                    info.setEndTime(System.currentTimeMillis());
                    
                    long bytes = 0;
                    long packets = 0;
                    
                    // TODO: If this is a FlowEntry, get byte and packet counts
                    if (flowRule instanceof FlowEntry) {
                        FlowEntry entry = (FlowEntry) flowRule;
                        bytes = entry.bytes();
                        packets = entry.packets();
                    }

                    log.info("TCP flow expired: {} -> {} ({}:{} -> {}:{})", 
                             srcMac, dstMac, 
                             Ip4Address.valueOf(srcIp), srcPort,
                             Ip4Address.valueOf(dstIp), dstPort);
                    
                    // TODO: Log the connection statistics
                    logTcpConnectionStats(connKey, info, bytes, packets);

                    // TODO: Clean up destination tracking if no more connections exist
                    Set<MacAddress> destinations = activeDestinations.get(srcMac);
                    if (destinations != null && !hasActiveConnectionsTo(srcMac, dstMac)) {
                        destinations.remove(dstMac);
                        log.debug("Removed destination {} from active set for {}", dstMac, srcMac);
                    }
                }
            } catch (Exception e) {
                log.error("Error processing TCP flow removal", e);
            }
        }

        /**
         * TODO: TASK 21 - Check for active TCP connections
         * 
         * Check if a source host has any active TCP connections to a destination.
         */
        private boolean hasActiveConnectionsTo(MacAddress srcMac, MacAddress dstMac) {
            // TODO: Search through tcpConnections map to find matching entries
            // HINT: Use Stream API to check if any connection matches
            return tcpConnections.entrySet().stream()
                .anyMatch(entry -> entry.getKey().srcMac.equals(srcMac) && 
                                   entry.getKey().dstMac.equals(dstMac));
        }
    }

    // ============================================================================
    // STATISTICS AND LOGGING
    // ============================================================================
    // ============================================================================
    // STATISTICS AND LOGGING
    // ============================================================================

    /**
     * TODO: TASK 22 - (OPTIONAL/ADVANCED) Implement flow statistics retrieval
     * 
     * Retrieves flow statistics from the switch and logs TCP connection stats.
     * This is an alternative approach - the main implementation gets stats from flow entries.
     */
    private void retrieveAndLogFlowStats(DeviceId deviceId, ConnectionKey connKey, TcpConnectionInfo info) {
        // TODO: Build selector to match the TCP flow
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_TCP)
                .matchEthSrc(connKey.srcMac)
                .matchEthDst(connKey.dstMac)
                .matchIPSrc(Ip4Prefix.valueOf(Ip4Address.valueOf(connKey.srcIp), 32))
                .matchIPDst(Ip4Prefix.valueOf(Ip4Address.valueOf(connKey.dstIp), 32))
                .matchTcpSrc(TpPort.tpPort(connKey.srcPort))
                .matchTcpDst(TpPort.tpPort(connKey.dstPort))
                .build();

        // TODO: Find matching flow entries on the device
        long totalBytes = 0;
        long totalPackets = 0;
        
        for (FlowEntry entry : flowRuleService.getFlowEntries(deviceId)) {
            if (entry.appId() == appId.id() && flowSelectorsMatch(entry.selector(), selector)) {
                totalBytes += entry.bytes();
                totalPackets += entry.packets();
                log.debug("Found flow entry - Bytes: {}, Packets: {}", entry.bytes(), entry.packets());
            }
        }

        // TODO: Log the statistics
        logTcpConnectionStats(connKey, info, totalBytes, totalPackets);
    }

    /**
     * TODO: TASK 23 - (OPTIONAL/ADVANCED) Implement selector matching
     * 
     * Check if two selectors match (for TCP flows).
     */
    private boolean flowSelectorsMatch(TrafficSelector entry, TrafficSelector target) {
        // TODO: Simple comparison - check if entry contains the TCP flow criteria
        return entry.getCriterion(Criterion.Type.ETH_TYPE) != null &&
               entry.getCriterion(Criterion.Type.IP_PROTO) != null &&
               target.criteria().stream().allMatch(c -> entry.criteria().contains(c));
    }

    /**
     * TODO: TASK 24 - Implement TCP connection statistics logging
     * 
     * Logs TCP connection statistics to a file.
     * QUESTION: Why log to a file instead of just using the ONOS logger?
     * ANSWER: _____________________________________________________________
     */
    private void logTcpConnectionStats(ConnectionKey connKey, TcpConnectionInfo info, 
                                       long bytes, long packets) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(LOG_FILE_PATH, true))) {
            // TODO: Format timestamp
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String timestamp = sdf.format(new Date());
            long duration = info.getDurationMs();

            // TODO: Create log entry with connection details
            String logEntry = String.format(
                "%s | SrcMAC: %s | DstMAC: %s | %s:%d -> %s:%d | Duration: %d ms | Bytes: %d | Packets: %d",
                timestamp, 
                connKey.srcMac, 
                connKey.dstMac,
                Ip4Address.valueOf(connKey.srcIp).toString(),
                connKey.srcPort,
                Ip4Address.valueOf(connKey.dstIp).toString(),
                connKey.dstPort,
                duration, 
                bytes, 
                packets
            );

            // TODO: Write to file
            writer.println(logEntry);
            log.info("Logged TCP connection stats: Bytes={}, Packets={}, Duration={}ms", bytes, packets, duration);
        } catch (IOException e) {
            log.error("Failed to write TCP connection statistics to file", e);
        }
    }

    /**
     * TODO: TASK 25 - Implement final statistics logging
     * 
     * Logs all active TCP connection statistics (called during deactivation).
     */
    private void logAllConnectionStats() {
        // TODO: Iterate through all tracked TCP connections
        for (Map.Entry<ConnectionKey, TcpConnectionInfo> entry : tcpConnections.entrySet()) {
            ConnectionKey connKey = entry.getKey();
            TcpConnectionInfo info = entry.getValue();
            
            // TODO: Set end time to current time
            info.setEndTime(System.currentTimeMillis());
            
            // TODO: Retrieve and log flow statistics
            retrieveAndLogFlowStats(info.deviceId, connKey, info);
        }
    }

    // ============================================================================
    // HELPER CLASSES
    // ============================================================================

    /**
     * TODO: TASK 26 - Understand the ConnectionKey class
     * 
     * Represents a unique connection identifier.
     * Used for both TCP tracking and general connection limiting.
     * 
     * QUESTION: Why do we need all these fields to identify a connection?
     * ANSWER: _____________________________________________________________
     */
    private static class ConnectionKey {
        final MacAddress srcMac;
        final MacAddress dstMac;
        final int srcIp;
        final int dstIp;
        final int srcPort;
        final int dstPort;

        ConnectionKey(MacAddress srcMac, MacAddress dstMac, int srcIp, int dstIp, int srcPort, int dstPort) {
            this.srcMac = srcMac;
            this.dstMac = dstMac;
            this.srcIp = srcIp;
            this.dstIp = dstIp;
            this.srcPort = srcPort;
            this.dstPort = dstPort;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            ConnectionKey that = (ConnectionKey) o;
            return srcIp == that.srcIp && dstIp == that.dstIp && 
                   srcPort == that.srcPort && dstPort == that.dstPort;
        }

        @Override
        public int hashCode() {
            return 31 * srcIp + 31 * dstIp + 31 * srcPort + dstPort;
        }
    }

    /**
     * TODO: TASK 27 - Understand the TcpConnectionInfo class
     * 
     * Tracks information for a TCP connection.
     * Stores device ID, MAC addresses, and timing information.
     * 
     * QUESTION: How is the duration calculated?
     * ANSWER: _____________________________________________________________
     */
    private static class TcpConnectionInfo {
        final DeviceId deviceId;
        final MacAddress srcMac;
        final MacAddress dstMac;
        private final long startTime;
        private long endTime;

        TcpConnectionInfo(DeviceId deviceId, MacAddress srcMac, MacAddress dstMac) {
            this.deviceId = deviceId;
            this.srcMac = srcMac;
            this.dstMac = dstMac;
            this.startTime = System.currentTimeMillis();
            this.endTime = 0;
        }

        void setEndTime(long endTime) {
            this.endTime = endTime;
        }

        long getDurationMs() {
            return (endTime > 0 ? endTime : System.currentTimeMillis()) - startTime;
        }
    }
}

