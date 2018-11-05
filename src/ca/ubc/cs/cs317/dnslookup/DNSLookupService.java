package ca.ubc.cs.cs317.dnslookup;

import java.io.Console;
import java.io.IOException;
import java.net.*;
import java.util.*;

import static java.lang.Math.abs;

public class DNSLookupService {

    private static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL = 10;

    private static InetAddress rootServer;
    private static boolean verboseTracing = false;
    private static DatagramSocket socket;
    private static InetAddress topLevelRootServer;
    private static String mostRecentCname;

    private static DNSCache cache = DNSCache.getInstance();

    private static Random random = new Random();

    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {

        if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            topLevelRootServer = InetAddress.getByName(args[0]);
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }

        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(5000);
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            // Use console if one is available, or standard input if not.
            String commandLine;
            if (console != null) {
                System.out.print("DNSLOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null) break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty()) continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") ||
                    commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        topLevelRootServer = InetAddress.getByName(commandArgs[1]);
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                        continue;
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    if (commandArgs[1].equalsIgnoreCase("on"))
                        verboseTracing = true;
                    else if (commandArgs[1].equalsIgnoreCase("off"))
                        verboseTracing = false;
                    else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
                    commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.
                RecordType type;
                if (commandArgs.length == 2)
                    type = RecordType.A;
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                mostRecentCname = commandArgs[1];
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            } else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup fqdn [type]");
                System.err.println("\ttrace on|off");
                System.err.println("\tserver IP");
                System.err.println("\tdump");
                System.err.println("\tquit");
                continue;
            }

        } while (true);

        socket.close();
        System.out.println("Goodbye!");
    }

    /**
     * Finds all results for a host name and type and prints them on the standard output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {
        DNSNode node = new DNSNode(hostName, type);
        printResults(node, getResults(node, 0));
    }

    /**
     * Finds all the result for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
     *                         The initial call should be made with 0 (zero), while recursive calls for
     *                         regarding CNAME results should increment this value by 1. Once this value
     *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
     *                         returns an empty set.
     * @return A set of resource records corresponding to the specific query requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {
        if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }

        try {
            if (cache.getCachedResults(node).size() > 0) { // Return from cache first if theres anything in the cache
                return cache.getCachedResults(node);
            }

            /**
            // Check if CName for this server already cached
            if (cache.getCachedResults(new DNSNode(node.getHostName(), RecordType.CNAME)).size() > 0) {
                ResourceRecord cnameRecord = new ArrayList<>(cache.getCachedResults(new DNSNode(node.getHostName(), RecordType.CNAME))).get(0);
                mostRecentCname = cnameRecord.getTextResult();
                DNSNode newNode = new DNSNode(mostRecentCname, node.getType());
                rootServer = topLevelRootServer;
                return getResults(newNode, ++indirectionLevel);
            }
             **/

          outerloop:
            while (true) { // TODO: Replace with while response is not authoritative
                // send and receive query
                int generatedId = abs(random.nextInt()) % 65535; // We want this to be the same if query is resent
                DNSResponseParser dnsResponseParser = sendAndReceiveQuery(node, rootServer, generatedId);

                if(dnsResponseParser == null) {
                    return Collections.emptySet(); // Socket timed out twice
                }

                dnsResponseParser.parse(); // Parse the response to update cache

                if (dnsResponseParser.getIsAuthoritativeAnswer() &&
                        cache.getCachedResults(node).size() > 0)  // If answer is authoritative and node is contained in cache, we have found the answer
                {
                    break;
                }
                /**
                else if (dnsResponseParser.getIsAuthoritativeAnswer() &&     // If the answer is authoritative and we have CNames
                        cache.getCachedResults(new DNSNode(node.getHostName(), RecordType.CNAME)).size() > 0)
                {
                    ArrayList<ResourceRecord> cnameResults = new ArrayList<>(cache.getCachedResults(new DNSNode(node.getHostName(), RecordType.CNAME)));
                    mostRecentCname = cnameResults.get(0).getTextResult();
                    DNSNode newNode = new DNSNode(mostRecentCname, node.getType());
                    rootServer = topLevelRootServer;
                    return getResults(newNode, ++indirectionLevel);
                }
                 **/
                else if (dnsResponseParser.getNSCOUNT() > 0) { // No auth answer returned by query but we got name servers
                    InetAddress targetNSIPAddress;
                    for (int i = 0; i < dnsResponseParser.nameServerDomainNames.size(); i++) {
                        String bufferDomainName = dnsResponseParser.nameServerDomainNames.get(i);

                        DNSNode nsNode = new DNSNode(bufferDomainName, RecordType.A);
                        ArrayList<ResourceRecord> cacheResults = new ArrayList<>();
                        cacheResults.addAll(cache.getCachedResults(nsNode));

                        // Check if cache has IPV4 Address for bufferDomainName NS
                        if (cacheResults.size() > 0) { // IP Address of NS is known
                            targetNSIPAddress = cacheResults.get(0).getInetResult();
                            InetAddress originalRootServer = rootServer;

                            // Change rootServer so query can be made with nameServer IPV4 Addr
                            rootServer = targetNSIPAddress;
                            getResults(node, indirectionLevel);
                            rootServer = originalRootServer; // Restore original rootServer

                            break outerloop; // No need to check the other NS, the recursive call will find the correct answer or give an empty set
                        }
                    }
                }
            }
        } catch (SocketException e) {
            System.err.println("SocketException: " + e.getMessage());
            return Collections.emptySet();
        } catch (IOException e) {
            System.err.println("IOException: " + e.getMessage());
            return Collections.emptySet();
        } catch (Exception e) {
            System.err.println(e.getMessage());
            return Collections.emptySet();
        }

        // Our execution flow guarantees that the cache will have the correct output or no output by this point
        return cache.getCachedResults(new DNSNode(mostRecentCname, node.getType()));
    }


    /**
     * Query is sent in iterative mode, and packet is received.
     * If there is a socketTimeout exception, then we retry the same query. If there is an exception again, we return null.
     *
     * @param node          Host name and record type to be used for the query.
     * @param queryServer   Address of the server to be used for the query.
     * @param transactionID transactionID for queryID. Need this parameter to keep transactionID the same
     * @return dnsResponseParser The DNSResponseParser initialized properly. It should be parsed
     */
    private static DNSResponseParser sendAndReceiveQuery(DNSNode node, InetAddress queryServer, int transactionID) throws Exception{
        DNSResponseParser dnsResponseParser;
        int timesSocketTimedOut = 0;
        outerloop:
        while(true){ // If socket times out, try again, if it happens again, fail
            try {
                dnsResponseParser = null;
                if(timesSocketTimedOut > 1){
                    break outerloop; // DNSResponse parser will be null
                }
                //generate the packet and send
                DNSQueryGenerator queryGenerator = new DNSQueryGenerator(node, verboseTracing);
                DatagramPacket query = queryGenerator.createPacket(queryServer, DEFAULT_DNS_PORT, transactionID);
                socket.send(query);

                //Wait for response
                DatagramPacket response;

                while (true) { // Keep receiving response until correct packet is received
                    response = new DatagramPacket(new byte[1024], 1024);

                    socket.receive(response);
                    dnsResponseParser = new DNSResponseParser(response, node, verboseTracing);
                    if (dnsResponseParser.checkValidTransactionID(queryGenerator.getGeneratedId())) {
                        break outerloop; // its a valid response so we know we got the right packet and DNSResponseParser is initialized properly
                    }
                }
            } catch(SocketTimeoutException e) {
                // Repeat call
                timesSocketTimedOut++;
            }
        }

        return dnsResponseParser;
    }

    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
     * and the query is repeated with a new server if the provided one is non-authoritative.
     * Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, InetAddress server) {

        // TODO To be completed by the student
    }

    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), record.getTTL(), record.getTextResult());
        }
    }
}
