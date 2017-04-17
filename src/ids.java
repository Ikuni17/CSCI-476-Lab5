/*
Bradley White and Isaac Sotelo
CSCI 476: Lab 5
April 11, 2017
 */

import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

//still need to compare host and attacker ports to policy
//figure how to deal with policy4, where to_host is
//stateful policy


public class ids {
    // Hashmap to hold the values of the policy
    static HashMap<String, ArrayList> hashmap = new HashMap<>();

    public static void main(String[] args) {

        // Read in policy file and populate the hashmap
        File file = new File(args[0]);
        if (file.isFile()) {

            BufferedReader inputStream = null;
            try {
                inputStream = new BufferedReader(new FileReader(file));
                String line;
                while ((line = inputStream.readLine()) != null) {
                    if (!line.isEmpty()) {
                        String[] parts = line.split("=");
                        if (hashmap.containsKey(parts[0])) {
                            parts[1] = parts[1].replaceAll("^\"|\"$", "");
                            hashmap.get(parts[0]).add(parts[1]);
                        } else {
                            parts[1] = parts[1].replaceAll("^\"|\"$", "");
                            hashmap.put(parts[0], new ArrayList<String>());
                            hashmap.get(parts[0]).add(parts[1]);
                        }
                    }
                }
            } catch (FileNotFoundException ex) {
                System.out.println("File not found");

            } catch (IOException ex) {
                System.out.println("IOException");
            }
        } else {
            System.out.println("File not found");
        }

        System.out.println("Current Policy Settings:");
        System.out.println(hashmap.toString());

        // Used by the PCAP library to process the packet capture
        final StringBuilder errbuf = new StringBuilder();

        // Open the packet capture which is passed as the second command line parameter
        final Pcap pcap = Pcap.openOffline(args[1], errbuf);

        if (pcap == null) {
            System.err.println(errbuf);
            return;
        }

        final PcapPacket packet = new PcapPacket(JMemory.POINTER);
        final Ip4 ip = new Ip4();
        final Tcp tcp = new Tcp();
        final Udp udp = new Udp();


        if (hashmap.containsKey("type")) {
            // Start the IDS as stateless
            if (hashmap.get("type").get(0).toString().equals("stateless")) {
                // Iterate through all packets in the capture
                while (pcap.nextEx(packet) == Pcap.NEXT_EX_OK) {
                    if (checkHost(packet, ip)) {
                        if (checkAttacker(packet, ip)) {
                            if (checkPayload(packet)) {
                                if (hashmap.get("proto").get(0).toString().equals("tcp")) {
                                    if (checkHostPort(packet, tcp)) {
                                        if (checkAtkPort(packet, tcp)) {
                                            System.out.println("IDS alerted by policy " + hashmap.get("name").get(0) + ".");
                                        }
                                    }
                                } else {
                                    if (checkHostPort(packet, udp)) {
                                        if (checkAtkPort(packet, udp)) {
                                            System.out.println("IDS alerted by policy " + hashmap.get("name").get(0) + ".");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // Else the IDS should be stateful
            else {
                // Iterate through all packets in the capture
                while (pcap.nextEx(packet) == Pcap.NEXT_EX_OK) {
                    if (checkHost(packet, ip)) {
                        if (checkAttacker(packet, ip)) {
                            if (checkPayload(packet)) {
                                if (checkHostPort(packet, tcp)) {
                                    if (checkAtkPort(packet, tcp)) {
                                        System.out.println("IDS alerted by policy " + hashmap.get("name").get(0) + ".");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            System.out.println("Please define the IDS as stateful or stateless in the policy file with type=<stateless|stateful>");
        }
    }


    //Check that the host IP address matches the policy host address

    private static boolean checkHost(PcapPacket packet, Ip4 ip) {
        if (hashmap.containsKey("host")) {
            // If the host can be anything, return true
            if (hashmap.get("host").get(0).toString().equals("any")) {
                return true;
            }
            //Check that the packet has an IP header
            if (packet.hasHeader(ip)) {
                // Compare the policy host IP to what the packet contains
                if (hashmap.get("host").get(0).toString().equals(FormatUtils.ip(ip.source()))) {
                    return true;
                }
            }
        }
        // Otherwise return false
        return false;
    }

    //Check that the host port matches the policy host port
    private static boolean checkHostPort(PcapPacket packet, Tcp tcp) {
        if (hashmap.containsKey("host_port")) {
            // If the port can be anything, return true
            if (hashmap.get("host_port").get(0).toString().equals("any")) {
                return true;
            }
            // Check that the packet has a TCP headers
            if (packet.hasHeader(tcp)) {
                //System.out.println("TCP Host Port: " + tcp.source());
                // Compare the policy host port to what the packet contains
                if (hashmap.get("host_port").get(0).toString().equals(String.valueOf(tcp.source()))) {
                    return true;
                }
            }
        }
        // Otherwise return false
        return false;
    }

    //Check that the attacker port matches the policy attacker port
    private static boolean checkAtkPort(PcapPacket packet, Tcp tcp) {
        if (hashmap.containsKey("attacker_port")) {
            // If the attacker port can be anything, return true
            if (hashmap.get("attacker_port").get(0).toString().equals("any")) {
                return true;
            }
            // Check that the packet has a TCP header
            if (packet.hasHeader(tcp)) {
                //System.out.println("TCP Atk Port: " + tcp.destination());
                // Compare the policy attacker port to what the packet contains
                if (hashmap.get("attacker_port").get(0).toString().equals(String.valueOf(tcp.destination()))) {
                    return true;
                }
            }
        }
        return false;
    }

    //Check that the host port matches the policy host port
    private static boolean checkHostPort(PcapPacket packet, Udp udp) {
        if (hashmap.containsKey("host_port")) {
            if (hashmap.get("host_port").get(0).toString().equals("any")) {
                return true;
            }
            //compare host port to policy
            if (packet.hasHeader(udp)) {
                //System.out.println("UDP Host Port: " + udp.source());
                if (hashmap.get("host_port").get(0).toString().equals(String.valueOf(udp.source()))) {
                    return true;
                }
            }
        }
        return false;
    }

    //Check that the attacker port matches the policy attacker port
    private static boolean checkAtkPort(PcapPacket packet, Udp udp) {
        if (hashmap.containsKey("attacker_port")) {
            if (hashmap.get("attacker_port").get(0).toString().equals("any")) {
                return true;
            }
            //compare attacker port to policy
            if (packet.hasHeader(udp)) {
                //System.out.println("UDP Atk Port: " + udp.destination());
                if (hashmap.get("attacker_port").get(0).toString().equals(String.valueOf(udp.destination()))) {
                    return true;
                }
            }
        }
        return false;
    }

    //Check that the attacker ip matches the policy attacker ip
    private static boolean checkAttacker(PcapPacket packet, Ip4 ip) {
        if (hashmap.containsKey("attacker")) {
            if (hashmap.get("attacker").get(0).toString().equals("any")) {
                return true;
            }
            //get host ip of packet
            if (packet.hasHeader(ip)) {
                //compare packet data to policy
                if (hashmap.get("host").get(0).toString().equals(FormatUtils.ip(ip.destination()))) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean checkPayload(PcapPacket packet) {
        Payload payload = new Payload();
        if (hashmap.containsKey("to_host")) {
            if (hashmap.get("to_host").get(0).toString().equals("any")) {
                return true;
            }

            if (packet.hasHeader(payload)) {
                String payloadAsString = payload.getUTF8String(0, payload.size());
                payloadAsString = payloadAsString.replaceAll("\n", "");
                //byte[] payloadContent = payload.getByteArray(0, payload.size());
                //System.out.println(new String(payloadContent));
                //System.out.println(payloadAsString);
                Iterator iter = hashmap.get("to_host").iterator();
                while (iter.hasNext()) {
                    if (iter.next().toString().equals(payloadAsString)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
