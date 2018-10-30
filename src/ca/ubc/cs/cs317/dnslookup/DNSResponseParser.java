package ca.ubc.cs.cs317.dnslookup;

import java.net.DatagramPacket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.lang.Math.abs;

public class DNSResponseParser {
    private static DNSCache cache = DNSCache.getInstance();
    private Map<Integer, String> compressionMap = new HashMap<>();
    private int currentDataIndex = 0;
    private byte[] data;
    private int sentId;
    private int parsedId;
    private int QDCOUNT;
    private int ANCOUNT;
    private int NSCOUNT;
    private int ARCOUNT;
    private DNSNode dnsNode;


    public DNSResponseParser(DatagramPacket packet, int sentId, DNSNode node) {
        this.sentId = sentId;
        this.data = packet.getData();
        this.dnsNode = node;
        parse();
    }

    private void parse() {
        parseHeader();
        parseQuestionSection();
        parseResourceRecords();
    }

    private void parseHeader() {
        this.parsedId =  convertToUnsignedInt(this.data[0], this.data[1]);
        //TODO don't know if we need to parse any of these small fields
        int QR = abs((int) data[2] >> 7);                   //should be 1
        this.QDCOUNT = convertToUnsignedInt(this.data[4], this.data[5]);
        this.ANCOUNT = convertToUnsignedInt(this.data[6], this.data[7]);
        this.NSCOUNT = convertToUnsignedInt(this.data[8], this.data[9]);
        this.ARCOUNT = convertToUnsignedInt(this.data[10], this.data[11]);
        this.currentDataIndex = 12;
    }

    private void parseQuestionSection() {
        for(int i = 0; i < this.QDCOUNT; i++){
            parseQuery();
        }
    }

    private void parseQuery() {
        parseLabelSequence();
        int qname = convertToUnsignedInt(this.data[currentDataIndex], this.data[currentDataIndex + 1]);
        currentDataIndex += 2;      // +2 for qname
        int qtype = convertToUnsignedInt(this.data[currentDataIndex], this.data[currentDataIndex + 1]);
        currentDataIndex += 2;      // +2 for qtype
    }

    private void parseResourceRecords() {
        int numResourceRecords = this.ANCOUNT + this.ARCOUNT + this.NSCOUNT;
        for(int i = 0; i < numResourceRecords; i++) {
            parseResourceRecord();
    }
    }

    private void parseResourceRecord(){
        String name = parseLabelSequence();
        RecordType type = RecordType.getByCode(convertToUnsignedInt(this.data[this.currentDataIndex], this.data[this.currentDataIndex + 1]));
        this.currentDataIndex += 2;
        int recordClass = convertToUnsignedInt(this.data[this.currentDataIndex], this.data[this.currentDataIndex + 1]);
        this.currentDataIndex += 2;
        long ttl = convertTo32BitLong();
        this.currentDataIndex += 4;
        int rdlength = convertToUnsignedInt(this.data[this.currentDataIndex], this.data[this.currentDataIndex + 1]);
        this.currentDataIndex += 2;
        if(type == RecordType.NS) {
            String rData = parseLabelSequence();
//            ResourceRecord resourceRecord = new ResourceRecord(dnsNode.getHostName(), dnsNode.getType(), ttl, rData);
//            cache.addResult(resourceRecord);
        } else if(type == RecordType.A){
            try {
                InetAddress addr = parseIPV4address();
                ResourceRecord resourceRecord = new ResourceRecord(this.dnsNode, ttl, name, addr);
                cache.addResult(resourceRecord);
            } catch (UnknownHostException e){
                System.err.println("Problem parsing IPV4address: " + e.getMessage());
            }
        } else if(type == RecordType.AAAA){
            try {
                InetAddress addr = parseIPV6address();
                ResourceRecord resourceRecord = new ResourceRecord(this.dnsNode, ttl, name, addr);
                cache.addResult(resourceRecord);
            } catch (UnknownHostException e){
                System.err.println("Problem parsing IPV6address: " + e.getMessage());
            }
        }
        //TODO add case parsing of answer CNAME's (maybe more)
    }

    private InetAddress parseIPV4address() throws UnknownHostException{
        InetAddress address = InetAddress.getByAddress(new byte[]{
                (byte)(this.data[this.currentDataIndex] & 0xFF),
                (byte)(this.data[this.currentDataIndex + 1] & 0xFF),
                (byte)(this.data[this.currentDataIndex + 2] & 0xFF),
                (byte)(this.data[this.currentDataIndex + 3] & 0xFF)});
        this.currentDataIndex += 4;
        return address;
    }

    private InetAddress parseIPV6address() throws UnknownHostException{
        //TODO this method does not work, need a new way to parse IPV6
        byte[] ipv6Bytes = new byte[16];
        for(int i = 0; i < 16; i++){
            ipv6Bytes[i] = (byte)(this.data[this.currentDataIndex] & 0xFF);
            this.currentDataIndex++;
        }
        return InetAddress.getByAddress(ipv6Bytes);
    }

    private int isPointer(byte byte1, byte byte2){
        if(((byte1 & 0xc0) >> 6) == 3) {
            return convertToUnsignedInt((byte)(byte1 & (0x3)), byte2);
        } else {
            return -1;
        }
    }

    private long convertTo32BitLong(){
        //source: https://stackoverflow.com/questions/13203426/convert-4-bytes-to-an-unsigned-32-bit-integer-and-storing-it-in-a-long
        long value = this.data[currentDataIndex + 3] & 0xFF;
        value |= (this.data[currentDataIndex + 2] << 8) & 0xFFFF;
        value |= (this.data[currentDataIndex + 1] << 16) & 0xFFFFFF;
        value |= (this.data[currentDataIndex] << 24) & 0xFFFFFFFF;
        return value;
    }
    private String parseLabelSequence() {
        List<Integer> labelStartIndexes = new ArrayList<>();
        List<String> labels = new ArrayList<>();
        int charLength = convertToUnsignedInt(this.data[this.currentDataIndex]);
        while(charLength != 0) {
            int isPointer = isPointer(this.data[this.currentDataIndex], this.data[this.currentDataIndex + 1]);
            if(isPointer > 0){
                labels.add(this.compressionMap.get(isPointer));
                labelStartIndexes.add(isPointer);
                this.currentDataIndex++;
                break;
            } else {
                labelStartIndexes.add(this.currentDataIndex);
                this.currentDataIndex++;
                char[] chars = new char[charLength];
                for (int i = 0; i < charLength; i++) {
                    chars[i] = (char) convertToUnsignedInt(this.data[this.currentDataIndex]);
                    this.currentDataIndex++;
                }
                labels.add(String.valueOf(chars));
            }
            charLength = convertToUnsignedInt(this.data[this.currentDataIndex]);
        }
        this.currentDataIndex++;
        updateCompressionCache(labels, labelStartIndexes);
        return String.join(".", labels);
    }

    private void updateCompressionCache(List<String> labels, List<Integer> labelStartIndexes) {
        for(int i = 0; i < labelStartIndexes.size(); i++) {
            if(!compressionMap.containsKey(labelStartIndexes.get(i))){
                compressionMap.put(labelStartIndexes.get(i), String.join(".", labels.subList(i, labelStartIndexes.size())));
            }
        }
    }

    private static int convertToUnsignedInt(byte byt) {
        if((byt >> 7) == -1){
            return ((byt & 0x7)) + 8;
        } else {
            return (int) byt;
        }
    }

    private static int convertToUnsignedInt(byte byte1, byte byte2){
        if( (byte1 >> 7) == -1){
            return (((byte1 & 0x7F) << 8) | byte2) + 32768;
        } else {
            return (byte1 << 8) | byte2;
        }
    }
}
