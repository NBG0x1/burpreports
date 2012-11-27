package com.burpunit;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScanQueueItem;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * BurpUnitizer uses the BurpExtender Interfaces for a headless usage of the 
 * spider and scanner of Burp Suite. As a result a unittest like file is 
 * generated. The file can be used on any Continuous Integrations systems to 
 * monitor the results.
 * 
 * @author runtz
 */
public class BurpUnitizer {

    private String URLS_TO_SCAN_FILE_NAME;
    private String RESULT_ZIP_FILE_NAME;
    private String RESULT_ISSUES_FILE_NAME;
    private String RESULT_URLS_FILE_NAME;
    private static final String RESULT_ZIP_FILE_POSTFIX = ".zip";
    private static final String RESULT_ISSUES_FILE_POSTFIX = ".issues";
    private static final String RESULT_URLS_FILE_POSTFIX = ".urls";
    private static final int SCAN_QUEUE_CHECK_INTERVALL = 2000;
    private File outsession;
    private BufferedWriter outissues;
    private BufferedWriter outurls;
    private BufferedReader urlsFromFileToScanReader;
    private IBurpExtenderCallbacks mcallBacks;
    private final List<IScanQueueItem> scanqueue = Collections.synchronizedList(new ArrayList<IScanQueueItem>());
    private final Map<String, String> outurlsList = new HashMap();
    private IScanQueueItem isqi;
    boolean serviceIsHttps = false;
    private boolean checkerStarted = false;

    /**
     * Enum for Burp Suite Tools.
     * 
     */
    private enum Tools {

        spider, scanner;
    }

    /**
     * Enum for several issues prios.
     */
    private enum IssuePriorities {

        Information, High;
    }

    /**
     * Convinience method for usage description
     */
    private void printUsage() {
        System.out.println("Usage: burp.sh [FILE WITH URLS TO SPIDER & SCAN] [FILENAME TO STORE REPORTS]");
    }

    /**
     * Constructor just writes some information on the console.
     */
    public BurpUnitizer() {
        System.out.println("##################################################");
        System.out.println("# Starting the headless spider & scanner for G+J #".toUpperCase());
        System.out.println("##################################################\n");
        printUsage();
    }

    /**
     * Delegate method from BurpExtender. Is called on startup of Burp Suite. 
     * Gets the console parameter passed. Initializes the programm.
     * 
     * @param args 
     */
    public void setCommandLineArgs(String[] args) {
        if (args.length == 2) {
            URLS_TO_SCAN_FILE_NAME = args[0];
            RESULT_ZIP_FILE_NAME = args[1] + RESULT_ZIP_FILE_POSTFIX;
            RESULT_ISSUES_FILE_NAME = args[1] + RESULT_ISSUES_FILE_POSTFIX;
            RESULT_URLS_FILE_NAME = args[1] + RESULT_URLS_FILE_POSTFIX;

            try {
                urlsFromFileToScanReader = new BufferedReader(new FileReader(URLS_TO_SCAN_FILE_NAME));
                outsession = new File(RESULT_ZIP_FILE_NAME);
                outissues = new BufferedWriter(new FileWriter(new File(RESULT_ISSUES_FILE_NAME), true));
                outurls = new BufferedWriter(new FileWriter(new File(RESULT_URLS_FILE_NAME), true));

                System.out.println("File Setup:\n---------------------------");
                System.out.println("1. URLS TO SCAN FILE: \t" + URLS_TO_SCAN_FILE_NAME);
                System.out.println("2. RESULT ZIP FILE: \t" + RESULT_ZIP_FILE_NAME);
                System.out.println("3. RESULT ISSUE FILE: \t" + RESULT_ISSUES_FILE_NAME);
                System.out.println("4. RESULT URL FILE: \t" + RESULT_URLS_FILE_NAME);
            } catch (Exception ex) {
                System.out.println("Error on command line setup: " + ex.getMessage());
                printUsage();
                System.exit(0);
            }
        } else {
            printUsage();
            System.exit(0);
        }
    }

    /**
     * Delegate method from BurpExtender. Is called for one time. Provides a callback 
     * reference. On the callback the scope gets defined from the loaded url list 
     * and the spider is called, both per each url list entry.
     * 
     * @param callbacks 
     */
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        mcallBacks = callbacks;

        String urlStringFromFile;
        URL urlFromFile;

        try {
            System.out.println("\nStarting the spider");
            while ((urlStringFromFile = urlsFromFileToScanReader.readLine()) != null) {
                System.out.print(urlStringFromFile);
                urlFromFile = new URL(urlStringFromFile);
                mcallBacks.includeInScope(urlFromFile);
                mcallBacks.sendToSpider(urlFromFile);
                System.out.println("\nStarting the scanner");
            }
        } catch (Exception ex) {
            System.out.println("Error while spidering: " + ex.getMessage());
            mcallBacks.exitSuite(false);
        }

    }

    /**
     * Delegate method from BurpExtender. Is called on each HTTP action, e.g. request 
     * and response. We are only interrested in response messages caused by the 
     * spider according to our scope to hand the massage over to the scanner. All
     * scan queue items get saved within a synchronized list. Only one time the scan 
     * queue checker is started to observe the scan queue as an observable.
     * 
     * @param toolName
     * @param messageIsRequest
     * @param messageInfo 
     */
    public void processHttpMessage(final String toolName, final boolean messageIsRequest, final IHttpRequestResponse messageInfo) {
        try {
            if (Tools.spider.toString().equals(toolName) && !messageIsRequest && mcallBacks.isInScope(messageInfo.getUrl())) {
                System.out.print(".");

                serviceIsHttps = "https".equals(messageInfo.getProtocol()) ? true : false;
                outurlsList.put(messageInfo.getUrl().toString(), messageInfo.getUrl().toString());

                isqi = mcallBacks.doActiveScan("localhost", 80, serviceIsHttps, messageInfo.getRequest());
                
                synchronized (scanqueue) {
                    scanqueue.add(isqi);
                }

                if (!checkerStarted) {
                    checkerStarted = true;
                    startScanQueueChecker(scanqueue);
                }
            }
        } catch (Exception ex) {
            System.out.println("Error while scanning: " + ex.getMessage());
            mcallBacks.exitSuite(false);
        }
    }

    /**
     * The scan queue checker defines and starts a thraed to monitor the items in 
     * the given scan queue for completness every x seconds. The scan queue item will 
     * be removed on a percentage of completness of 100.
     * 
     * @param scanqueue 
     */
    private void startScanQueueChecker(final List<IScanQueueItem> scanqueue) {
        (new Thread() {
            @Override
            public void run() {
                try {
                    while (!scanqueue.isEmpty()) {
                        System.out.println("\nChecking scan queue:" + new Date());

                        IScanQueueItem currentItem;

                        synchronized (scanqueue) {
                            for (Iterator<IScanQueueItem> currentQueueItemIt = scanqueue.iterator(); currentQueueItemIt.hasNext();) {

                                currentItem = currentQueueItemIt.next();
                                System.out.println("Item:" + currentItem.getPercentageComplete());

                                if (currentItem.getPercentageComplete() == 100) {
                                    currentQueueItemIt.remove();
                                }
                            }
                        }

                        this.sleep(SCAN_QUEUE_CHECK_INTERVALL);
                        this.yield();
                    }
                    mcallBacks.exitSuite(false);
                } catch (InterruptedException ex) {
                    System.out.println("Error on check thread: " + ex.getMessage());
                    mcallBacks.exitSuite(false);
                }
            }
        }).start();
    }

    /**
     * Delegate method from BurpExtender. Is called on each issue found. Saves the 
     * found issue descriptions.
     * 
     * @param issue 
     */
    public void newScanIssue(IScanIssue issue) {
        try {
            if (!IssuePriorities.Information.toString().equals(issue.getSeverity())) {
                System.out.println("scanner: " + issue.getSeverity() + " " + issue.getIssueName() + ": " + issue.getUrl());
            }

            outissues.write(issue.getUrl() + "\t"
                    + issue.getIssueName() + "\t"
                    + issue.getIssueBackground() + "\t"
                    + issue.getIssueDetail() + "\t"
                    + issue.getRemediationBackground() + "\t"
                    + issue.getSeverity() + " (" + issue.getConfidence() + ")\n");
        } catch (Exception e) {
            System.out.println("Error writing to issue file: " + e.getMessage());
        }
    }

    /**
     * Saves the state of Burp with all settings, found issues etc. to a file. This 
     * file could be open within Burp.
     * 
     * @throws IOException 
     */
    private void saveStateToFile() throws IOException {
        try {
            mcallBacks.saveState(outsession);

            Iterator<String> scannedURLsIT = outurlsList.keySet().iterator();
            while (scannedURLsIT.hasNext()) {
                outurls.write(scannedURLsIT.next() + "\n");
            }
        } catch (Exception ex) {
            System.out.println("Error writing to urls + sessions files: " + ex.getMessage());
            mcallBacks.exitSuite(false);
        }
    }

    /**
     * Delegate method from BurpExtender. Is called after invoking exitSuite on 
     * the Burp callback handle.
     */
    public void applicationClosing() {
        try {
            saveStateToFile();
            outurls.close();
            outissues.close();
        } catch (Exception ex) {
            System.out.println("Error: " + ex.getMessage());
            System.exit(0);
        }
    }
}
