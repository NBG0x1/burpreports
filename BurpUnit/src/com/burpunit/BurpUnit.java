package com.burpunit;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScanQueueItem;
import com.burpunit.cfg.BurpUnitConfig;
import com.burpunit.cfg.BurpUnitConfig.GeneralSettings.BurpConfigOverwrites.Property;
import com.burpunit.cfg.BurpUnitConfig.ReportWriter;
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
import javax.xml.bind.JAXB;

/**
 * ATTENTION: COMPILE WITH JDK6!!!
 *
 * SET THE CORRECT FOLDER OF THE BURP SUITE DISTRIBUTION IN BUILD:XML!
 *
 * BurpUnit uses the BurpExtender Interfaces for a headless usage of the spider
 * and scanner of Burp Suite. Several report writer could be registered to
 * generate reports. The XUnitReportWriter report can be used for an Continuous
 * Integrations systems to monitor the results.
 *
 * @author runtz
 */
public class BurpUnit {

    private String urlsToScanFileName;
    private String resultBurpFileName;
    private String resultUrlsFileName;
    private static final String RESULT_BURP_FILE_POSTFIX = ".burp";
    private static final String RESULT_URLS_FILE_POSTFIX = ".urls";
    private int SCAN_QUEUE_CHECK_INTERVALL = 2000;
    private int MAX_SCAN_QUEUE_SIZE = 100;
    private File outsession;
    private BufferedWriter outurls;
    private BufferedReader urlsFromFileToScanReader;
    private IBurpExtenderCallbacks mcallBacks;
    private final List<IScanQueueItem> scanqueue = Collections.synchronizedList(new ArrayList<IScanQueueItem>());
    private IScanQueueItem isqi;
    private boolean serviceIsHttps = false;
    private boolean checkerStarted = false;
    long startMillis;
    private String burpConfigPropertiesFileName;
    private List<IssueReportWritable> issueReportWritableObjectList;
    private List<ReportWriter> reportWriterConfigList;
    private BurpUnitConfig burpUnitConfig;

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
        System.out.println("Usage: burp.sh [RESULT FILE SIBBLING, E.G. <SITE>_<YYMMDD>] [OPT: FILENAME PATH OF THE BURP UNIT CONFIGURATION FILE]");
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
        if (args.length > 0 && args.length < 3) {
            String resultsFileNameSibling = "";

            if (args.length > 0) {
                resultsFileNameSibling = args[0];
            }

            if (args.length == 2) {
                burpConfigPropertiesFileName = args[1];
            } else {
                burpConfigPropertiesFileName = "burp_unit_config.xml";
            }

            resultBurpFileName = resultsFileNameSibling + RESULT_BURP_FILE_POSTFIX;
            resultUrlsFileName = resultsFileNameSibling + RESULT_URLS_FILE_POSTFIX;

            try {

                burpUnitConfig = JAXB.unmarshal(new FileInputStream(new File(burpConfigPropertiesFileName)), BurpUnitConfig.class);
                reportWriterConfigList = burpUnitConfig.getReportWriter();

                System.out.println("Loading the following IssueReportWritabeles:");
                issueReportWritableObjectList = new ArrayList<IssueReportWritable>();
                for (ReportWriter reportWriterConfig : reportWriterConfigList) {
                    System.out.println(reportWriterConfig.getFullQualifiedClassName());
                    Class c = Class.forName(reportWriterConfig.getFullQualifiedClassName());
                    issueReportWritableObjectList.add(((IssueReportWritable) c.newInstance()).initilizeIssueReportWriter(reportWriterConfig, resultsFileNameSibling));
                }

                urlsToScanFileName = burpUnitConfig.getGeneralSettings().getUrlListFilepath().getPath();

                System.out.println("File Setup:\n---------------------------");
                System.out.println("1. BURP CONFIG PROP FILE: \t" + burpConfigPropertiesFileName);
                System.out.println("2. URLS TO SCAN FILE: \t" + urlsToScanFileName);
                System.out.println("3. RESULT URL FILE: \t" + resultUrlsFileName);
                System.out.println("4. RESULT BURP FILE: \t" + resultBurpFileName);
                System.out.println("5. REPORT WRITABLES:");

                for (IssueReportWritable issueReportWriterService : issueReportWritableObjectList) {
                    System.out.println("- " + issueReportWriterService.getOutputFilePath());
                }

                urlsFromFileToScanReader = new BufferedReader(new FileReader(urlsToScanFileName));
                outsession = new File(resultBurpFileName);
                outurls = new BufferedWriter(new FileWriter(resultUrlsFileName));

                if (burpUnitConfig.getGeneralSettings().getScanQueueCheckInterval().getMilliseconds() != null) {
                    SCAN_QUEUE_CHECK_INTERVALL = burpUnitConfig.getGeneralSettings().getScanQueueCheckInterval().getMilliseconds().intValue();
                    System.out.println("SCAN_QUEUE_CHECK_INTERVALL: \t" + SCAN_QUEUE_CHECK_INTERVALL);
                }

                if (burpUnitConfig.getGeneralSettings().getScanQueueCheckInterval().getMilliseconds() != null) {
                    MAX_SCAN_QUEUE_SIZE = burpUnitConfig.getGeneralSettings().getMaxScanQueueSize().getSize().intValue();
                    System.out.println("MAX_SCAN_QUEUE_SIZE: \t" + MAX_SCAN_QUEUE_SIZE);
                }

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

    private void loadBurpConfigPropertiesFromFile(final IBurpExtenderCallbacks mcallBacks, final List<Property> propertyList) {
        Map<String, String> configMap = new HashMap();

        System.out.println("\nSetting the following properties:");
        for (Property prop : propertyList) {
            System.out.println("\n" + prop.getName() + ":" + prop.getValue());
            configMap.put(prop.getName(), prop.getValue());
        }
        mcallBacks.loadConfig(configMap);
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

        loadBurpConfigPropertiesFromFile(mcallBacks, burpUnitConfig.getGeneralSettings().getBurpConfigOverwrites().getProperty());

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

                if (MAX_SCAN_QUEUE_SIZE > scanqueue.size()) {
                    isqi = mcallBacks.doActiveScan(messageInfo.getHost(), 80, serviceIsHttps, messageInfo.getRequest());

                    synchronized (scanqueue) {
                        scanqueue.add(isqi);
                    }
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

            for (IssueReportWritable issueReportWriterService : issueReportWritableObjectList) {
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

            for (IssueReportWritable issueReportWriterService : issueReportWritableObjectList) {
                issueReportWriterService.closeReport();
            }
            System.out.println("Total time: " + (System.currentTimeMillis() - startMillis));
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
