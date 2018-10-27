package ca.ubc.cs.cs317.dnslookup;

import java.net.DatagramPacket;
import java.net.InetAddress;
import java.util.Random;

import static java.lang.Math.abs;

public class DNSQueryGenerator {
    private static Random random = new Random();
    private int bufferLength;
    private byte[] buffer;
    private DNSNode node;
    private int generatedId;


    public DNSQueryGenerator(DNSNode node) {
        this.buffer = new byte[256];
        this.node = node;
    }

    public DatagramPacket createPacket(InetAddress rootServer, int port) {
        generateHeaderSection(this.buffer);
        generateQuestionSection(this.buffer, this.node);
        return new DatagramPacket(this.buffer, this.bufferLength, rootServer, port);
    }


    private void generateHeaderSection(byte[] buf){
        this.generatedId = abs(random.nextInt()) % 65535;                       // Create a new id, 16bit so modulo 65535 to ensure no overflow
        buf[0] = (byte) (this.generatedId >>> 8);                                 //assign ID to first two bytes
        buf[1] = (byte) (this.generatedId & (0xFF));
        buf[2] = (byte) 0;                                          //sets QR, OpCode, AA, and TC to 0
        buf[3] = (byte) 0;                                          //sets RA, Z, Rcode to 0
        buf[4] = (byte) 0;                                          //sets QDcount to 1 (we ask 1 question)
        buf[5] = (byte) 1;
        buf[6] = (byte) 0;                                          //sets ANcount to 0 (no answers in query)
        buf[7] = (byte) 0;
        buf[8] = (byte) 0;                                          //sets NSCount to 0 (no name server RR's)
        buf[9] = (byte) 0;
        buf[10] = (byte) 0;                                         //sets ARCount to 0 no RR's in additional section
        buf[11] = (byte) 0;
    }

    private void generateQuestionSection(byte[] buf, DNSNode node) {
        int currentOffset = 12;                                                  //Header section takes up 12 bytes
        String address = node.getHostName();
        String[] splitAddress = address.split("\\.");                       //seperates address into subdomains ex: ["www","google","com"]
        for(String addressPart : splitAddress){
            int addresPartLength = addressPart.length();
            buf[currentOffset] = (byte) (addresPartLength & (0xFF));             //inserts length of subdomain into buffer
            currentOffset++;
            for(int i = 0; i < addresPartLength; i++) {                          //this loop inserts individual character ASCII codes into buffer
                char c = addressPart.charAt(i);
                buf[currentOffset] = (byte) ((int) c & (0xFF));
                currentOffset++;
            }
        }
        buf[currentOffset] = (byte) 0;                                          //inserts 00 terminating code
        currentOffset ++;
        buf[currentOffset] = (byte) 0;                                           //inserts 1 as Qtype for host address
        currentOffset ++;
        buf[currentOffset] = (byte) 1;
        currentOffset++;
        buf[currentOffset] = (byte) 0;                                          //inserts 1 as Qclass for host address
        currentOffset ++;
        buf[currentOffset] = (byte) 1;
        this.bufferLength = currentOffset + 1;                                               //add 1 for 0 based index
    }

    public int getGeneratedId() {
        return generatedId;
    }
}
