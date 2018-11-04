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
    private boolean isVerbose;


    public DNSQueryGenerator(DNSNode node, boolean isVerbose) {
        this.buffer = new byte[256];
        this.node = node;
        this.isVerbose = isVerbose;
    }

    public DatagramPacket createPacket(InetAddress rootServer, int port, int generatedId) {
        this.generatedId = generatedId;
        generateHeaderSection(this.buffer);
        generateQuestionSection(this.buffer, this.node);
        if(this.isVerbose){
            System.out.print("\n\n"); // for each query that is sent, print 2 blank lines
            System.out.println("Query ID     " + this.generatedId
            +  " " + this.node.getHostName()
            +  "  " + this.node.getType()
            + " --> " + rootServer.getHostAddress());
        }
        return new DatagramPacket(this.buffer, this.bufferLength, rootServer, port);
    }


    private void generateHeaderSection(byte[] buf){
        buf[0] = (byte) (this.generatedId >>> 8);                                 //assign ID to first two bytes
        buf[1] = (byte) (this.generatedId & (0xFF));
        buf[2] = (byte) 0;                                          //sets QR to 0 cause query, OpCode 0 for standard query, AA, RD and TC to 0
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
        currentOffset = insertQType(buf, currentOffset);
////        buf[currentOffset] = (byte) 0;                                          //inserts 1 as Qtype for host address
////        currentOffset ++;
//        buf[currentOffset] = (byte) 1;
//        currentOffset++;
//        buf[currentOffset] = (byte) 0;                                          //inserts 1 as Qclass for IN
        currentOffset ++;
        buf[currentOffset] = (byte) 1;
        this.bufferLength = currentOffset + 1;                                               //add 1 for 0 based index
    }

    private int insertQType(byte[] buf, int currentOffset) {
        int code = this.node.getType().getCode();
        switch (this.node.getType()){
            case A:
                buf[currentOffset] = 0;
                currentOffset++;
                buf[currentOffset] = 0x01;
                currentOffset++;
                break;
            case AAAA:              //code = 28
                buf[currentOffset] = 0;
                currentOffset++;
                buf[currentOffset] = 0x1C;
                currentOffset++;
                break;
            case NS:
                buf[currentOffset] = 0;
                currentOffset++;
                buf[currentOffset] = 0x02;
                currentOffset++;
                break;
            case MX:                //code = 15
                buf[currentOffset] = 0;
                currentOffset++;
                buf[currentOffset] = 0x0F;
                currentOffset++;
                break;
            case CNAME:
                buf[currentOffset] = 0;
                currentOffset++;
                buf[currentOffset] = 0x05;
                currentOffset++;
                break;
        }
        return currentOffset;
    }

    public int getGeneratedId() {
        return generatedId;
    }
}
