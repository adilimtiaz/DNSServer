package ca.ubc.cs.cs317.dnslookup;

import java.net.DatagramPacket;

import static java.lang.Math.abs;

public class DNSResponseParser {
    private DatagramPacket packet;
    private int sentId;
    private int parsedId;
    private int QDCOUNT;
    private int ANCOUNT;
    private int NSCOUNT;
    private int ARCOUNT;

    public DNSResponseParser(DatagramPacket packet, int sentId) {
        this.sentId = sentId;
        this.packet = packet;
        parse();
    }

    public void parse() {
        byte[] data = this.packet.getData();
        parseHeader(data);
    }

    private void parseHeader(byte[] data) {
        this.parsedId =  convertToUnsignedInt(data[0], data[1]);

        int QR = abs((int) data[2] >> 7);                   //should be 1
        //TODO don't know if we need to parse any of these small fields

        this.QDCOUNT = convertToUnsignedInt(data[4], data[5]);
        this.ANCOUNT = convertToUnsignedInt(data[6], data[7]);
        this.NSCOUNT = convertToUnsignedInt(data[8], data[9]);
        this.ARCOUNT = convertToUnsignedInt(data[10], data[11]);
    }

    private static int convertToUnsignedInt(byte byt) {
        //TODO I don't know if this will be used but it requires additonal testing to make sure it works right
        if((int) (byt >> 7) == -1){
            return (int) (byt & 0x7) + 8;
        } else {
            return (int) byt;
        }
    }

    private static int convertToUnsignedInt(byte byte1, byte byte2){
        if( (byte1 >> 7) == -1){
            return ((int) ((byte1 & 0x7F) << 8) | byte2) + 32768;
        } else {
            return (byte1 << 8) | byte2;
        }
    }
}
