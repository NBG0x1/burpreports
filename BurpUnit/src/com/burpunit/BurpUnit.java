package com.burpunit;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScanQueueItem;
import com.burpunit.cfg.BurpUnitConfig;
import com.burpunit.report.IssueReportWritable;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import javax.xml.bind.JAXB;

/**
 * ATTENTION: COMPILE WITH JDK6!!!
 * 
 * SET THE CORRECT FOLDER OF THE BURP SUITE DISTRIBUTION IN BUILD:XML!
 * 
 * BurpUnit uses the BurpExtender Interfaces for a headless usage of the
 * spider and scanner of Burp Suite. Several report writer could be registered 
 * to generate reports. The XUnitReportWriter report can be used for an 
 * Continuous Integrations systems to monitor the results.
 *
 * @author runtz
 */
public class BurpUnit {

    private String urlsToScanFileName;
    private String resultBurpFileName;
    private String resultIssuesFileName;
    private String resultUrlsFileName;
    private String resultXUnitFileName;
    private static final String RESULT_BURP_FILE_POSTFIX = ".burp";
    private static final String RESULT_ISSUES_FILE_POSTFIX = ".html";
    private static final String RESULT_URLS_FILE_POSTFIX = ".urls";
    private static final String RESULT_XUNIT_FILE_POSTFIX = ".xml";
    private static final int SCAN_QUEUE_CHECK_INTERVALL = 2000;
    private File outsession;
    private BufferedWriter outurls;
    private BufferedReader urlsFromFileToScanReader;
    private IBurpExtenderCallbacks mcallBacks;
    private final List<IScanQueueItem> scanqueue = Collections.synchronizedList(new ArrayList<IScanQueueItem>());
//    private final Map<String, String> outurlsList = new HashMap();
    private IScanQueueItem isqi;
    private boolean serviceIsHttps = false;
    private boolean checkerStarted = false;
    private Map<String, String> propMap;
    private Map<String, String> configMap;
    private BufferedReader configMapFileToRead;
    private BufferedWriter configMapFileToWrite;
    long startMillis;
    private String burpConfigPropertiesFileName;
    private ServiceLoader<IssueReportWritable> issueReportWriterServices;

    /**
     * Enum for Burp Suite Tools.
     *
     */
    private enum Tools {

        spider, scanner;
    }

    public static enum BurpUnitProperties {

        URLS_TO_SCAN_FILE_NAME, RESULT_BURP_FILE_NAME, RESULT_ISSUES_FILE_NAME, RESULT_URLS_FILE_NAME, RESULT_XUNIT_FILE_NAME, BURP_CONFIG_PROPERTIES_FILE_NAME;
    }

    /**
     * Enum for several issues prios.
     */
    public static enum IssuePriorities {

        Information, Medium, High;
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
    public BurpUnit() {
        startMillis = System.currentTimeMillis();
        System.out.println("##########################################");
        System.out.println("# Starting the headless spider & scanner #".toUpperCase());
        System.out.println("##########################################\n");
        printUsage();
    }

    /**
     * Delegate method from BurpExtender. Is called on startup of Burp Suite.
     * Gets the console parameter passed. Initializes the programm.
     *
     * @param args
     */
    public void setCommandLineArgs(String[] args) {
        if (args.length == 3) {
            urlsToScanFileName = args[0];
            resultBurpFileName = args[1] + RESULT_BURP_FILE_POSTFIX;
            resultIssuesFileName = args[1] + RESULT_ISSUES_FILE_POSTFIX;
            resultUrlsFileName = args[1] + RESULT_URLS_FILE_POSTFIX;
            resultXUnitFileName = args[1] + RESULT_XUNIT_FILE_POSTFIX;
            burpConfigPropertiesFileName = args[2];

            try {

                BurpUnitConfig burpUnitConfig = JAXB.unmarshal(new FileInputStream(new File("burp_unit_config.xml")), BurpUnitConfig.class);
                                
                urlsFromFileToScanReader = new BufferedReader(new FileReader(urlsToScanFileName));
                outsession = new File(resultBurpFileName);
                outurls = new BufferedWriter(new FileWriter(resultUrlsFileName));

                System.out.println("File Setup:\n---------------------------");
                System.out.println("1. URLS TO SCAN FILE: \t" + urlsToScanFileName);
                System.out.println("2. RESULT BURP FILE: \t" + resultBurpFileName);
                System.out.println("3. RESULT ISSUE FILE: \t" + resultIssuesFileName);
                System.out.println("4. RESULT URL FILE: \t" + resultUrlsFileName);
                System.out.println("5. RESULT XUNIT FILE: \t" + resultXUnitFileName);
                System.out.println("6. BURP CONFIG PROP FILE: \t" + burpConfigPropertiesFileName);
                System.out.println("7. CONFIG:" + burpUnitConfig.getGeneralSettings().getMaxScanQueueSize().getSize());

                propMap = new HashMap();
                propMap.put(BurpUnitProperties.URLS_TO_SCAN_FILE_NAME.toString(), urlsToScanFileName);
                propMap.put(BurpUnitProperties.RESULT_BURP_FILE_NAME.toString(), resultBurpFileName);
                propMap.put(BurpUnitProperties.RESULT_ISSUES_FILE_NAME.toString(), resultIssuesFileName);
                propMap.put(BurpUnitProperties.RESULT_URLS_FILE_NAME.toString(), resultUrlsFileName);
                propMap.put(BurpUnitProperties.RESULT_XUNIT_FILE_NAME.toString(), resultXUnitFileName);
                propMap.put(BurpUnitProperties.BURP_CONFIG_PROPERTIES_FILE_NAME.toString(), burpConfigPropertiesFileName);

                issueReportWriterServices = ServiceLoader.load(IssueReportWritable.class);
                System.out.println("Loading the following IssueReportWritabeles:");
                for (IssueReportWritable issueReportWriterService : issueReportWriterServices) {
                    System.out.println(issueReportWriterService.getClass());
                    issueReportWriterService.initilizeIssueReportWriter(propMap);
                }
                
                //IssueReportWritable irw = IssueReportWritable.class.cast(Class.forName("com.burpunit.report.HTMLReportWriter"));
                
            } catch (Exception ex) {
                ex.printStackTrace();
                printUsage();
                System.exit(0);
            }
        } else {
            printUsage();
            System.exit(0);
        }
    }

    private void loadBurpConfigPropertiesFromFile(final IBurpExtenderCallbacks mcallBacks, final String burpConfigPropertiesFileName) {
        try {
            configMapFileToRead = new BufferedReader(new FileReader(burpConfigPropertiesFileName));
            String propSplitArray[];
            configMap = new HashMap();

            System.out.println("\nSetting the following properties:");
            for (String propertyKeyValueString; (propertyKeyValueString = configMapFileToRead.readLine()) != null;) {
                System.out.println("\n" + propertyKeyValueString);
                propSplitArray = propertyKeyValueString.split("=");
                if (propSplitArray.length == 2) {
                    configMap.put(propSplitArray[0], propSplitArray[1]);
                }
            }
            mcallBacks.loadConfig(configMap);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    /**
     * Delegate method from BurpExtender. Is called for one time. Provides a
     * callback reference. On the callback the scope gets defined from the
     * loaded url list and the spider is called, both per each url list entry.
     *
     * @param callbacks
     */
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        mcallBacks = callbacks;

        loadBurpConfigPropertiesFromFile(mcallBacks, burpConfigPropertiesFileName);
//        saveBurpConfigPropertiesToFile(mcallBacks, "config_map_final.txt");

        URL urlFromFile;

        try {
            System.out.println("\nStarting the spider");
            for (String urlStringFromFile; (urlStringFromFile = urlsFromFileToScanReader.readLine()) != null;) {
                System.out.print(urlStringFromFile);
                urlFromFile = new URL(urlStringFromFile);
                mcallBacks.includeInScope(urlFromFile);
                mcallBacks.sendToSpider(urlFromFile);
                System.out.println("\nStarting the scanner");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            mcallBacks.exitSuite(false);
        }

    }

    /**
     * Delegate method from BurpExtender. Is called on each HTTP action, e.g.
     * request and response. We are only interrested in response messages caused
     * by the spider according to our scope to hand the massage over to the
     * scanner. All scan queue items get saved within a synchronized list. Only
     * one time the scan queue checker is started to observe the scan queue as
     * an observable.
     *
     * @param toolName
     * @param messageIsRequest
     * @param messageInfo
     */
    public void processHttpMessage(final String toolName, final boolean messageIsRequest, final IHttpRequestResponse messageInfo) {
        try {
            if (Tools.spider.toString().equals(toolName) && !messageIsRequest && mcallBacks.isInScope(messageInfo.getUrl())) {

                serviceIsHttps = "https".equals(messageInfo.getProtocol()) ? true : false;
                outurls.write(messageInfo.getUrl().toString() + "\n");

                isqi = mcallBacks.doActiveScan(messageInfo.getHost(), 80, serviceIsHttps, messageInfo.getRequest());

                synchronized (scanqueue) {
                    scanqueue.add(isqi);
                }

                if (!checkerStarted) {
                    checkerStarted = true;
                    startScanQueueChecker(scanqueue);
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            mcallBacks.exitSuite(false);
        }
    }

    /**
     * The scan queue checker defines and starts a thraed to monitor the items
     * in the given scan queue for completness every x seconds. The scan queue
     * item will be removed on a percentage of completness of 100.
     *
     * @param scanqueue
     */
    private void startScanQueueChecker(final List<IScanQueueItem> scanqueue) {
        (new Thread() {
            @Override
            public void run() {
                try {
                    while (!scanqueue.isEmpty()) {
                        System.out.println("\nChecking scan queue: \t" + new Date());
                        System.out.println("\nCurrent Queue size: \t" + scanqueue.size());

                        IScanQueueItem currentItem;

                        synchronized (scanqueue) {
                            for (Iterator<IScanQueueItem> currentQueueItemIt = scanqueue.iterator(); currentQueueItemIt.hasNext();) {
                                currentItem = currentQueueItemIt.next();
                                if (currentItem.getPercentageComplete() == 100) {
                                    currentQueueItemIt.remove();
                                }
                            }
                        }

                        Thread.sleep(SCAN_QUEUE_CHECK_INTERVALL);
                    }
                    mcallBacks.exitSuite(false);
                } catch (InterruptedException ex) {
                    ex.printStackTrace();
                    mcallBacks.exitSuite(false);
                }
            }
        }).start();
    }

    /**
     * Delegate method from BurpExtender. Is called on each issue found. Saves
     * the found issue descriptions.
     *
     * @param issue
     */
    public void newScanIssue(IScanIssue issue) {
        try {

            for (IssueReportWritable issueReportWriterService : issueReportWriterServices) {
                issueReportWriterService.addIssueToReport(issue);
            }

            if (!IssuePriorities.Information.toString().equals(issue.getSeverity())) {
                System.out.println("scanner: " + issue.getSeverity() + " " + issue.getIssueName() + ": " + issue.getUrl());

                (new Runnable() {
                    @Override
                    public void run() {
                        try {
                            mcallBacks.saveState(outsession);
                        } catch (Exception ex) {
                            ex.printStackTrace();
                        }
                    }
                }).run();

            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Delegate method from BurpExtender. Is called after invoking exitSuite on
     * the Burp callback handle.
     */
    public void applicationClosing() {
        try {
            outurls.close();

            for (IssueReportWritable issueReportWriterService : issueReportWriterServices) {
                issueReportWriterService.closeReport();
            }
            System.out.println("Total time: " + (System.currentTimeMillis() - startMillis));
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
