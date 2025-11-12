# ONOS Learning Bridge - Student Assignment Guide

Welcome! This is your starter template for implementing an ONOS Learning Bridge application with advanced features.

## 📚 What You'll Learn

In this assignment, you will implement a Software-Defined Networking (SDN) application that:

1. **Learns MAC addresses** and their associated switch ports
2. **Limits connections** per host (max simultaneous connections to different destinations)
3. **Tracks TCP statistics** (bytes, packets, duration) and logs them
4. **Manages flow rules** with automatic timeout and cleanup

## 🎯 Learning Objectives

By completing this assignment, you will understand:

- How SDN controllers process packets
- How flow rules work in OpenFlow switches
- How to implement MAC address learning
- How to enforce network policies (connection limiting)
- How to track and log network statistics
- How flow lifecycle management works

## 📋 Prerequisites

Before starting, make sure you have:

1. ✅ Read the [GETTING_STARTED.md](GETTING_STARTED.md) guide. 
2. ✅ Set up Mininet VM and tested connectivity
3. ✅ Reviewed the [ONOS_DEVELOPMENT_GUIDE.md](ONOS_DEVELOPMENT_GUIDE.md)

## 📝 Assignment Structure

The code is organized with **27 TODO tasks** grouped into logical sections:

### Part 1: Application Setup (Tasks 1-5)
- Understand ONOS service references
- Implement application activation/deactivation
- Set up packet processing infrastructure

### Part 2: Packet Processing (Tasks 6-15)
- Extract packet information
- Implement MAC address learning
- Add connection limiting logic
- Implement flow rule installation
- Handle packet flooding

### Part 3: Flow Management (Tasks 16-21)
- Listen for flow removal events
- Clean up connection tracking
- Handle TCP flow expiry
- Retrieve flow statistics

### Part 4: Statistics & Logging (Tasks 22-27)
- Log TCP connection statistics
- Understand helper classes
- Implement cleanup on shutdown

## 🚀 How to Complete the Assignment

### Step 1: Read the Code Structure

Open `src/main/java/org/onosproject/learningbridge/LearningBridgeApp.java` and review:

- The imports and service references
- The data structures (macTables, activeDestinations, tcpConnections)
- The configuration constants (MAX_CONNECTIONS_PER_HOST, FLOW_TIMEOUT)

### Step 2: Work Through the TODOs

The code is already complete with detailed TODO comments. Your job is to:

1. **Understand each TODO** - Read the comments and hints
2. **Answer the questions** - Fill in the answers in the code comments
3. **Verify the implementation** - The code is already there, but make sure you understand it
4. **Test your understanding** - Try modifying values and see what happens

### Step 3: Answer the Embedded Questions

Throughout the code, you'll find QUESTION/ANSWER pairs like this:

```java
// QUESTION: Why should we exclude broadcast and multicast traffic from connection limits?
// ANSWER: _____________________________________________________________
```

Fill in these answers to demonstrate your understanding.

### Step 4: Test Your Application

1. **Build the application:**
   ```bash
   ./build.sh
   ```

2. **Install in ONOS:**
   ```bash
   onos-cli
   onos> bundle:install -s file:/workspaces/OnosSDNstudent/target/learning-bridge-1.0-SNAPSHOT.jar
   ```

3. **Test in Mininet:**
   ```bash
   # From Mininet VM
   sudo ./start-mininet.py <HOST_IP>
   
   mininet> pingall
   ```

4. **Verify connection limiting:**
   ```bash
   mininet> xterm h1 h1 h1
   
   # In first h1 terminal:
   h1# ping 10.0.0.2  # Should work ✅
   
   # In second h1 terminal:
   h1# ping 10.0.0.3  # Should work ✅
   
   # In third h1 terminal:
   h1# ping 10.0.0.4  # Should be BLOCKED ❌
   ```

5. **Test TCP statistics:**
   ```bash
   mininet> xterm h1 h2
   
   # In h2 terminal:
   h2# iperf -s
   
   # In h1 terminal:
   h1# iperf -c 10.0.0.2 -t 10
   
   # Wait for flow to expire, then check:
   tail /tmp/tcp_connections.log
   ```

### Step 5: Experiment and Learn

Try modifying these values and observe the behavior:

1. **Change MAX_CONNECTIONS_PER_HOST:**
   - Set to 1: Only one connection per host
   - Set to 5: Five connections per host
   - What happens when you exceed the limit?

2. **Change FLOW_TIMEOUT:**
   - Set to 10 seconds: Flows last longer
   - Set to 3 seconds: Flows expire quickly
   - How does this affect connection cleanup?

3. **Monitor the logs:**
   ```bash
   tail -f /opt/onos/apache-karaf-*/data/log/karaf.log | grep LearningBridge
   ```

## 🔍 Key Concepts to Understand

### 1. MAC Address Learning

The learning bridge learns which MAC addresses are reachable through which ports:

```
Device: switch1
  MAC aa:bb:cc:dd:ee:ff -> Port 1
  MAC 11:22:33:44:55:66 -> Port 2
```

### 2. Connection Limiting

Each host can only have MAX_CONNECTIONS_PER_HOST active destinations:

```
Host h1 (00:00:00:00:00:01):
  Connected to: [00:00:00:00:00:02, 00:00:00:00:00:03]
  Connection to 00:00:00:00:00:04: BLOCKED (limit reached)
```

### 3. Flow Rules

Instead of processing every packet, we install flow rules in the switch:

```
Match: src=h1, dst=h2, port=1 -> Action: forward to port 2
```

### 4. Flow Lifecycle

1. Packet arrives (packet-in)
2. Controller processes and learns MAC
3. Controller installs flow rule
4. Subsequent packets handled by switch (no packet-in)
5. Flow times out after FLOW_TIMEOUT seconds
6. FlowListener receives removal event
7. Controller cleans up connection tracking

## 📊 Expected Output

### Successful Ping Test
```bash
mininet> h1 ping h2
PING 10.0.0.2 (10.0.0.2) 56(84) bytes of data.
64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=x.xx ms
```

### Blocked Connection (3rd connection)
```bash
mininet> h1 ping h4
# No response - packets dropped by controller
```

### ONOS Log Output
```
Learning Bridge Application Started (Student Version) - Max connections: 2
Learned: 00:00:00:00:00:01 -> port 1 on device of:0000000000000001
Tracking new TCP connection: 00:00:00:00:00:01 -> 00:00:00:00:00:02:80
Connection limit reached for host 00:00:00:00:00:01. Dropping packet to new destination 00:00:00:00:00:04
Connection ended: 00:00:00:00:00:01 -> 00:00:00:00:00:02. Active destinations: 1
```

### TCP Statistics Log (/tmp/tcp_connections.log)
```
2025-11-12 10:30:45 | SrcMAC: 00:00:00:00:00:01 | DstMAC: 00:00:00:00:00:02 | 10.0.0.1:54321 -> 10.0.0.2:5001 | Duration: 10234 ms | Bytes: 1048576 | Packets: 728
```

## 🐛 Troubleshooting

### Problem: Application won't build
```bash
# Solution: Check Java version
java -version  # Should be Java 11

# Clean and rebuild
./build.sh
```

### Problem: Flows not being installed
```bash
# Check ONOS apps are activated
onos-cli
onos> apps -s -a  # Should show openflow, hostprovider, lldpprovider
```

### Problem: Connection limiting not working
```bash
# Check logs for "Connection limit reached" messages
tail -f /opt/onos/apache-karaf-*/data/log/karaf.log | grep "Connection limit"
```

### Problem: No TCP statistics logged
```bash
# Ensure flow timeout has passed
# Check if file exists and is writable
ls -la /tmp/tcp_connections.log

# Check ONOS logs for errors
tail -f /opt/onos/apache-karaf-*/data/log/karaf.log | grep "TCP"
```

## 📖 Additional Resources

- [ONOS Wiki](https://wiki.onosproject.org/)
- [OpenFlow Specification](https://www.opennetworking.org/software-defined-standards/specifications/)
- [Mininet Documentation](http://mininet.org/walkthrough/)
- [ONOS Developer Guide](https://wiki.onosproject.org/display/ONOS/Developer+Quick+Start)

## ✅ Submission Checklist

Before submitting, ensure you have:

- [ ] Answered all QUESTION/ANSWER pairs in the code
- [ ] Successfully built the application
- [ ] Tested MAC address learning (pingall works)
- [ ] Verified connection limiting (3rd connection blocked)
- [ ] Confirmed TCP statistics are logged
- [ ] Documented any issues or observations
- [ ] Cleaned up and tested final version

## 💡 Tips for Success

1. **Read the hints carefully** - They guide you to the solution
2. **Test incrementally** - Don't try to implement everything at once
3. **Use the logs** - They show you what's happening
4. **Experiment** - Try changing values and see what happens
5. **Ask questions** - If you're stuck, consult the documentation or ask for help

## 🎓 Going Further (Optional Challenges)

Want to extend your learning? Try these:

1. **Add UDP statistics logging** (similar to TCP)
2. **Implement per-port connection limits** (not just per-host)
3. **Add a REST API** to query current connections
4. **Implement connection timeout** (remove inactive connections)
5. **Add support for IPv6**

Good luck, and enjoy learning about SDN! 🚀
