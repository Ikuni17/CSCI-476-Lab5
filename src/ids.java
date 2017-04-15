/*
Bradley White and Isaac Sotelo
CSCI 476: Lab 5
April 11, 2017
 */

import java.io.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;

import com.sun.xml.internal.ws.api.message.Packet;
import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.annotate.Protocol;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import sun.security.x509.IPAddressName;

//still need to compare host and attacker ports to policy
//figure how to deal with policy4, where to_host is
//stateful policy


public class ids {
    static HashMap<String, ArrayList> hashmap = new HashMap<>();
    public static void main(String[] args) {

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
                            hashmap.get(parts[0]).add(parts[1]);
                        } else {
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

        // Iterate through all packets in the capture
        while (pcap.nextEx(packet) == Pcap.NEXT_EX_OK) {
            // Check the packet headers
            if (hashmap.containsKey("type")) {
                if (hashmap.get("type").get(0).toString().equals("stateless")) { //Using a stateless policy

                    if (hashmap.containsKey("proto") && hashmap.get("proto").get(0).toString().equals("tcp")) {

                        if (State.checkHost(packet,ip)) {
                            if (State.checkHostPort(packet,ip)) {
                                if (State.checkAtkPort(packet,ip)) {
                                    if (State.checkAttacker(packet,ip)) {
                                        if (Stateless.checkPayload(packet,ip)){
                                            System.out.println("IDS alerted by policy " + hashmap.get("name").get(0) + ".");
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else { //Using a stateless policy


                }
            }
        }
    }

    //methods used in either Stateful or Stateless
    public static class State {
        static final Tcp tcp = new Tcp();
        static final Udp udp = new Udp();

        //Check that the host matches the policy host
        private static boolean checkHost(PcapPacket packet, Ip4 ip) {
            if(hashmap.containsKey("host")) {
                if (hashmap.get("host").get(0).toString().equals("any")) {
                    return true;
                }
                //get host ip of packet
                if(packet.hasHeader(ip)) {
                    String host = FormatUtils.ip(ip.source());

                    //compare packet data to policy
                    if (hashmap.get("host").get(0).toString().equals(host)) {
                        return true;
                    }
                }
            }
            return false;
        }
        //Check that the host port matches the policy host port
        private static boolean checkHostPort(PcapPacket packet, Ip4 ip) {
            if(hashmap.containsKey("host_port")) {
                if (hashmap.get("host_port").get(0).toString().equals("any")) {
                    return true;
                }
                //compare host port to policy
            }
            return false;
        }
        //Check that the attacker port matches the policy attacker port
        private static boolean checkAtkPort(PcapPacket packet, Ip4 ip) {
            if(hashmap.containsKey("attacker_port")) {
                if (hashmap.get("attacker_port").get(0).toString().equals("any")) {
                    return true;
                }
                //compare attacker port to policy
            }
            return false;
        }
        //Check that the attacker ip matches the policy attacker ip
        private static boolean checkAttacker(PcapPacket packet, Ip4 ip) {
            if(hashmap.containsKey("attacker")) {
                if (hashmap.get("attacker").get(0).toString().equals("any")) {
                    return true;
                }
                //get host ip of packet
                if(packet.hasHeader(ip)) {
                    String host = FormatUtils.ip(ip.destination());

                    //compare packet data to policy
                    if (hashmap.get("host").get(0).toString().equals(host)) {
                        return true;
                    }
                }
            }
            return false;
        }
    }

    public static class Stateless {
        Tcp tcp = new Tcp();
        Udp udp = new Udp();

        private static boolean checkPayload(PcapPacket packet, Ip4 ip) {
            return false;
        }
    }

    public static class Stateful {
        Tcp tcp = new Tcp();
        Udp udp = new Udp();

        private static boolean checkPayload(PcapPacket packet) {
            return false;
        }

    }

    public static String convertHexToString(String hex) {

        StringBuilder sb = new StringBuilder();
        StringBuilder temp = new StringBuilder();

        //49204c6f7665204a617661 split into two characters 49, 20, 4c...
        for (int i = 0; i < hex.length() - 1; i += 2) {
            //grab the hex in pairs
            String output = hex.substring(i, (i + 2));
            //convert hex to decimal
            int decimal = Integer.parseInt(output, 16);
            //convert the decimal to character
            sb.append((char) decimal);
            temp.append(decimal);
        }
        return sb.toString();
    }

    public static Boolean checkPayload(PcapPacket packet) {
//        JBuffer storage = new JBuffer(JMemory.Type.POINTER);
//        JBuffer payload = protocol.peerPayloadTo(storage);
//        //System.out.println(payload.toHexdump());
//        if (payload.size() > 0) {
//            final byte[] data = payload.getByteArray(0, payload.size());
//            String hexString = new BigInteger(data).toString(16);
//            if (!hexString.equals("0")) {
//                System.out.println(convertHexToString(hexString));
//            }
//        }
        return false;
    }
}
//System.out.println(packet.toString());
//payload = packet.getPayload(payload);


//System.out.println(payload.toString());

                 /*
                // If the packet has the SYN flag set and not the ACK flag, we keep track of the source IP and the amount of packets sent
                if (tcp.flags_SYN() && !tcp.flags_ACK()) {
                    // Check if the IP is already in the HashMap, if not add it and increment the SYN sent count by 1
                    if (hashmap.containsKey(FormatUtils.ip(ip.source()))) {
                        hashmap.get(FormatUtils.ip(ip.source()))[0]++;
                    } else {
                        hashmap.put(FormatUtils.ip(ip.source()), new int[2]);
                        hashmap.get(FormatUtils.ip(ip.source()))[0]++;
                    }
                    // If the SYN and ACK flags are set, this is a reply to a SYN packet and we keep track of the destination IP and the amount of packets received
                } else if (tcp.flags_SYN() && tcp.flags_ACK()) {
                    // Check if the IP is already in the HashMap, if not add it and increment the SYN/ACK received count by 1
                    if (hashmap.containsKey(FormatUtils.ip(ip.destination()))) {
                        hashmap.get(FormatUtils.ip(ip.destination()))[1]++;
                    } else {
                        hashmap.put(FormatUtils.ip(ip.destination()), new int[2]);
                        hashmap.get(FormatUtils.ip(ip.destination()))[1]++;
                    }
                }*/


