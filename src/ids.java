/*
Bradley White and Isaac Sotelo
CSCI 476: Lab 5
April 11, 2017
 */

import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

public class ids {
    public static void main(String[] args) {
        HashMap<String, ArrayList> hashmap = new HashMap<>();
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
            }
        } else {
            System.out.println("File not found");
        }

        System.out.println(hashmap.toString());
        System.out.println(hashmap.get("host_port").get(0));

        // Used by the PCAP library to process the packet capture
        final StringBuilder errbuf = new StringBuilder();

        // Open the packet capture which is passed as the first command line parameter
        final Pcap pcap = Pcap.openOffline(args[1], errbuf);

        if (pcap == null) {
            System.err.println(errbuf);
            return;
        }
    }
}