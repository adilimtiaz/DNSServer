package ca.ubc.cs.cs317.dnslookup;

import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

public class DNSResponseParser {
    private static DNSCache cache = DNSCache.getInstance();
    private int currentDataIndex = 0;
    private byte[] data;
    private int parsedId;
    private int QDCOUNT;
    private int ANCOUNT;
    private int NSCOUNT;
    private int ARCOUNT;
    private DNSNode dnsNode;
    private boolean isAuthoritativeAnswer;
    private boolean isVerbose;
    public ArrayList<String> nameServerDomainNames;


    public DNSResponseParser(DatagramPacket packet, DNSNode node, boolean isVerbose) {
        this.data = packet.getData();
        this.dnsNode = node;
        this.isVerbose = isVerbose;
        nameServerDomainNames = new ArrayList<>();
    }

    public void parse() throws Exception{
        parseHeader();
        parseQuestionSection();
        parseResourceRecords();
    }

    private void parseHeader() throws Exception {
        this.parsedId =  convertToUnsignedInt(this.data[0], this.data[1]);
        this.isAuthoritativeAnswer = getNthBitFromLeftForByte(6, this.data[2]) > 0;
        failIfTruncated(getNthBitFromLeftForByte(7, this.data[2]));
        int RCODE = 0;
        for(int i=5; i<8;i++){
            RCODE = ((RCODE << 1) | getNthBitFromLeftForByte(i, this.data[3]));
        }
        processRcode(RCODE);
        this.QDCOUNT = convertToUnsignedInt(this.data[4], this.data[5]);
        this.ANCOUNT = convertToUnsignedInt(this.data[6], this.data[7]);
        this.NSCOUNT = convertToUnsignedInt(this.data[8], this.data[9]);
        this.ARCOUNT = convertToUnsignedInt(this.data[10], this.data[11]);
        if (this.isVerbose){
            System.out.println("Response ID: " + this.parsedId
            + " Authoritative = " + this.isAuthoritativeAnswer);
        }
        this.currentDataIndex = 12;
    }

    // If false, then this is not the response for query
    public boolean checkValidTransactionID(int queryTID){
        int responseTID = convertToUnsignedInt(this.data[0], this.data[1]);
        return (queryTID==responseTID);
    }

    private void parseQuestionSection() {
        for(int i = 0; i < this.QDCOUNT; i++){
            parseQuery();
        }
    }

    private void parseQuery() {
        parseDomainName(this.currentDataIndex);
        int qname = convertToUnsignedInt(this.data[currentDataIndex], this.data[currentDataIndex + 1]);
        currentDataIndex += 2;      // +2 for qname
        int qtype = convertToUnsignedInt(this.data[currentDataIndex], this.data[currentDataIndex + 1]);
        currentDataIndex += 2;      // +2 for qtype
    }

    private void parseResourceRecords() {
        if(this.isVerbose)
            System.out.println("  Answers (" + this.ANCOUNT + ")");
        for(int i = 0; i < this.ANCOUNT; i++) {
            parseResourceRecord();
        }
        if(this.isVerbose)
            System.out.println("  Nameservers (" + this.NSCOUNT + ")");
        for(int i = 0; i < this.NSCOUNT; i++) {
            parseResourceRecord();
        }
        if(this.isVerbose)
            System.out.println("  Additional information (" + this.ARCOUNT + ")");
        for(int i = 0; i < this.ARCOUNT; i++) {
            parseResourceRecord();
        }
    }

    private void parseResourceRecord(){
        String name = parseDomainName(this.currentDataIndex);
        // parseDomainName updates the data index
        RecordType type = RecordType.getByCode(convertToUnsignedInt(this.data[this.currentDataIndex], this.data[this.currentDataIndex + 1]));
        this.currentDataIndex += 2;
        int recordClass = convertToUnsignedInt(this.data[this.currentDataIndex], this.data[this.currentDataIndex + 1]);
        this.currentDataIndex += 2;
        long ttl = convertTo32BitLong();
        this.currentDataIndex += 4;
        int rDataLength = convertToUnsignedInt(this.data[this.currentDataIndex], this.data[this.currentDataIndex + 1]);
        this.currentDataIndex += 2;
        if(type == RecordType.A) {
            try {
                InetAddress addr = parseIPV4address();
                ResourceRecord resourceRecord = new ResourceRecord(name, type, ttl, addr);
                cache.addResult(resourceRecord);
                verbosePrintResourceRecord(resourceRecord, type.getCode());
            } catch (UnknownHostException e){
                System.err.println("Problem parsing IPV4address: " + e.getMessage());
            }
        } else if(type == RecordType.AAAA){
            try {
                InetAddress addr = parseIPV6address();
                ResourceRecord resourceRecord = new ResourceRecord(name, type, ttl, addr);
                cache.addResult(resourceRecord);
                verbosePrintResourceRecord(resourceRecord, type.getCode());
            } catch (UnknownHostException e){
                System.err.println("Problem parsing IPV6address: " + e.getMessage());
            }
        }
        else if (type == RecordType.NS){
            String nameServerName = parseDomainName(this.currentDataIndex);
            nameServerDomainNames.add(nameServerName);
            ResourceRecord resourceRecord = new ResourceRecord(name, type, ttl, nameServerName);
            cache.addResult(resourceRecord);
            verbosePrintResourceRecord(resourceRecord, type.getCode());
        } else if (type == RecordType.CNAME){
            String CName = parseDomainName(this.currentDataIndex);
            ResourceRecord resourceRecord = new ResourceRecord(name, type, ttl, CName);
            cache.addResult(resourceRecord);
            verbosePrintResourceRecord(resourceRecord, type.getCode());
        } else{  //case for finding a record we are not expected to get any data out of
            parseDomainName(this.currentDataIndex);
            ResourceRecord resourceRecord = new ResourceRecord(name, type, ttl, "----");
            verbosePrintResourceRecord(resourceRecord, type.getCode());
        }
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
        byte[] ipv6Bytes = new byte[16];
        for(int i = 0; i < 16; i++){
            ipv6Bytes[i] = (byte)(this.data[this.currentDataIndex] & 0xFF);
            this.currentDataIndex++;
        }
        return InetAddress.getByAddress(ipv6Bytes);
    }

    private boolean isPointer(byte inputByte){
        return ( (getNthBitFromLeftForByte (1, inputByte)> 0)
                && (getNthBitFromLeftForByte(2, inputByte) > 0));
    }

    private long convertTo32BitLong(){
        //source: https://stackoverflow.com/questions/13203426/convert-4-bytes-to-an-unsigned-32-bit-integer-and-storing-it-in-a-long
        long value = this.data[currentDataIndex + 3] & 0xFF;
        value |= (this.data[currentDataIndex + 2] << 8) & 0xFFFF;
        value |= (this.data[currentDataIndex + 1] << 16) & 0xFFFFFF;
        value |= (this.data[currentDataIndex] << 24) & 0xFFFFFFFF;
        return value;
    }

    private String parseDomainName(int dataOffset) {
        List<String> labels = new ArrayList<>();
        int currentByte = convertToUnsignedInt(this.data[dataOffset]);
        while(currentByte != 0  && !isPointer((byte) (currentByte & 0xFF))) {
            int labelLength = currentByte;
            dataOffset++;
            char[] chars = new char[labelLength];
            for (int i = 0; i < labelLength; i++) {
                chars[i] = (char) convertToUnsignedInt(this.data[dataOffset]);
                dataOffset++;
            }
            String labelContent = (String.valueOf(chars));
            labels.add(labelContent);
            currentByte = convertToUnsignedInt(this.data[dataOffset]);
        }

        String domainName = String.join(".", labels);
        if (isPointer((byte) (currentByte & 0xFF))) {
            int twoBytesIncludingTheOffset = convertToUnsignedInt(this.data[dataOffset], this.data[dataOffset + 1]);
            int pointerOffset = twoBytesIncludingTheOffset & 0b0011111111111111;
            String domainNameOfPointer = parseDomainName(pointerOffset);
            if(domainName.length() > 0) {
                domainName = domainName.concat(".");
            }
            domainName = domainName.concat(domainNameOfPointer);
            dataOffset++;
        }

        this.currentDataIndex = dataOffset+1;
        return domainName;
    }

    private void processRcode(int rCode) throws Exception {
        switch(rCode){
            case(0):
                break;
            case(1):
                throw new Exception("Format error - The name server was unable to interpret the query.");
            case(2):
                throw new Exception("Server failure - The name server was unable to " +
                        "process this query due to a problem with the name server.");
            case(3):
                throw new Exception("Name Error - The domain name referenced in the query does not exist");
            case(4):
                throw new Exception(" Not Implemented - The name server does\n" +
                        "                                not support the requested kind of query");
            case(5):
                throw new Exception("Refused - The name server refuses to\n" +
                        "                                perform the specified operation for\n" +
                        "                                policy reasons.");
        }
    }

    private void failIfTruncated(int truncatedBit) throws Exception{
        if(truncatedBit == 1) {
            throw new Exception("Failed because response was too large");
        }
    }

    private static int convertToUnsignedInt(byte byte1) {
        return byte1 & 0xFF;
    }

    private static int convertToUnsignedInt(byte byte1, byte byte2){
        int ret = 0;
        ret |= byte1 & 0xFF;
        ret <<=8;
        ret |= byte2 & 0xFF;
        return ret;
    }

    public int getNthBitFromLeftForByte(int position, Byte input){
        return (input>>(8-position)) & 1;
    }

    private void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (this.isVerbose)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }

    public boolean getIsAuthoritativeAnswer(){
        return this.isAuthoritativeAnswer;
    }

    public ArrayList<String> getResponseNameServerDomainNames(){
        return this.nameServerDomainNames;
    }
}
