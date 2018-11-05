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

        try {
            if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
                System.err.println("Maximum number of indirection levels reached.");
                return Collections.emptySet();
            }

            // Return from cache first if theres anything in the cache
            if (cache.getCachedResults(node).size() > 0) {
                return cache.getCachedResults(node);
            }

            // send and receive query
            DNSResponseParser dnsResponseParser = sendAndReceiveQuery(node, rootServer);

            if (dnsResponseParser == null) {
                return Collections.emptySet(); // Socket timed out twice
            }
            // If answer is authoritative and node is contained in cache

            if (dnsResponseParser.getIsAuthoritativeAnswer()) {
                Set<ResourceRecord> answers = cache.getCachedResults(node);

                boolean CNAMEsfound = false;
                boolean correctAnswerTypeFound = false;
                for (ResourceRecord answer : answers) {
                    if (answer.getType() == RecordType.CNAME) {
                        System.out.println("Found CNAME : " + answer.toString());
                        CNAMEsfound = true;
                    }

                    if (answer.getType() == node.getType()) {
                        correctAnswerTypeFound = true;
                    }
                }

                if (correctAnswerTypeFound) {
                    return cache.getCachedResults(node);
                }

                if (CNAMEsfound) {
                    // Do a query to resolve CNAME
                    return Collections.emptySet();
                }
            } else { // No auth answer returned by query but we got name servers
                ArrayList<String> nsNamesFromThisResponse = dnsResponseParser.getResponseNameServerDomainNames();
                boolean atLeastOneNSHasIPAddress = false;

                // Try to see if at least one NS has an IP Address that can be resolved
                for (int i = 0; i < nsNamesFromThisResponse.size(); i++) {
                    InetAddress NSIPAddress = resolveNSInetAddr(nsNamesFromThisResponse.get(i), indirectionLevel);
                    if (NSIPAddress != null) {
                        atLeastOneNSHasIPAddress = true;
                        // If an iP Address is found, start a new query to update cache
                        // Change rootServer to NSIPAddress
                        InetAddress tmpRootServer = rootServer;
                        rootServer = NSIPAddress;
                        getResults(node, indirectionLevel);
                        rootServer = tmpRootServer; //Restore orignial rootServer
                        break;
                    }
                }

                // If no address could be resolved, no answers could be found
                if (!atLeastOneNSHasIPAddress) {
                    return Collections.emptySet();
                }

                return cache.getCachedResults(node);
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
        return cache.getCachedResults(node);
    }

    public static InetAddress resolveNSInetAddr(String nsDomainName, int indirectionLevel) {
        // Check if cache has IPV4 Address for bufferDomainName NS
        InetAddress nsIPAddr = null;
        DNSNode nsNode = new DNSNode(nsDomainName, RecordType.A);
        ArrayList<ResourceRecord> nameServerAddresses = new ArrayList<>();
        nameServerAddresses.addAll(cache.getCachedResults(nsNode));

        if (nameServerAddresses.size() > 0) {
            nsIPAddr = nameServerAddresses.get(0).getInetResult();
        } else {
            // Cache does not have address for NS, HENCE make new query to resolve NS
            Set<ResourceRecord> IPAddressesFound = getResults(nsNode, indirectionLevel);
            ArrayList<ResourceRecord> IPAddressList = new ArrayList<>();
            IPAddressList.addAll(IPAddressesFound);
            if (IPAddressList.size() > 0) {
                nsIPAddr = IPAddressList.get(0).getInetResult();
            }
        }

        return nsIPAddr;
    }

    /**
     * Query is sent in iterative mode, and packet is received.
     * If there is a socketTimeout exception, then we retry the same query. If there is an exception again, we return null.
     *
     * @param node        Host name and record type to be used for the query.
     * @param queryServer Address of the server to be used for the query.
     * @return dnsResponseParser The DNSResponseParser initialized properly. It should be parsed
     */
    private static DNSResponseParser sendAndReceiveQuery(DNSNode node, InetAddress queryServer) throws Exception {
        int transactionID = abs(random.nextInt()) % 65535; // We want this to be the same if query is resent
        DNSResponseParser dnsResponseParser;
        int timesSocketTimedOut = 0;
        outerloop:
        while (true) { // If socket times out, try again, if it happens again, fail
            try {
                dnsResponseParser = null;
                if (timesSocketTimedOut > 1) {
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
                        dnsResponseParser.parse(); // Parse the response to update cache
                        break outerloop; // its a valid response so we know we got the right packet and DNSResponseParser is initialized properly
                    }
                }
            } catch (SocketTimeoutException e) {
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
