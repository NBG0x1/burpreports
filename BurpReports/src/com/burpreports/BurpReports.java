package com.burpreports;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScanQueueItem;
import com.burpreports.cfg.BurpReportsConfig;
import com.burpreports.cfg.BurpReportsConfig.GeneralSettings.BurpConfigOverwrites.Property;
import com.burpreports.cfg.BurpReportsConfig.ReportWriter;
import com.burpreports.report.IssueReportWritable;
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
 * SET THE CORRECT FOLDER OF THE BURP SUITE DISTRIBUTION IN BUILD.XML!
 *
 * BurpReports uses the BurpExtender Interfaces for a headless usage of the spider
 * and scanner of Burp Suite. Several report writer could be registered to
 * generate reports. The XUnitReportWriter report can be used for an Continuous
 * Integrations systems to monitor the results.
 *
 * @author runtz
 */
public class BurpReports {

    private String urlsToScanFileName;
    private String resultUrlsFileName;
    private String resultsFileNameSibling;
    private static final String RESULT_URLS_FILE_POSTFIX = ".urls";
    private int SCAN_QUEUE_CHECK_INTERVALL = 2000;
    private int MAX_SCAN_QUEUE_SIZE = 100;
    private static final String BURP_REPORTS_DEFAULT_CONFIG = "burp_reports_config.xml";
    private BufferedWriter outurls;
    private BufferedReader urlsFromFileToScanReader;
    private IBurpExtenderCallbacks mcallBacks;
    private final List<IScanQueueItem> scanqueue = Collections.synchronizedList(new ArrayList<IScanQueueItem>());
    private IScanQueueItem isqi;
    private boolean serviceIsHttps = false;
    private boolean checkerStarted = false;
    long startMillis;
    private String burpConfigPropertiesFileName;
    private List<IssueReportWritable> issueReportWritableObjectsList;
    private List<ReportWriter> reportWriterConfigList;
    private BurpReportsConfig burpUnitConfig;
    private boolean maxScanQueueSizeExceeded;

    /**
     * Enum for Burp Suite Tools.
     *
     */
    private enum Tools {

        spider, scanner;
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
    public BurpReports() {
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
            if (args.length > 0) {
                resultsFileNameSibling = args[0];
            }

            if (args.length == 2) {
                burpConfigPropertiesFileName = args[1];
            } else {
                burpConfigPropertiesFileName = BURP_REPORTS_DEFAULT_CONFIG;
            }


            resultUrlsFileName = resultsFileNameSibling + RESULT_URLS_FILE_POSTFIX;

            try {

                burpUnitConfig = JAXB.unmarshal(new FileInputStream(new File(burpConfigPropertiesFileName)), BurpReportsConfig.class);
                reportWriterConfigList = burpUnitConfig.getReportWriter();

                urlsToScanFileName = burpUnitConfig.getGeneralSettings().getUrlListFilepath().getPath();

                System.out.println("File Setup:\n---------------------------");
                System.out.println("1. BURP CONFIG PROP FILE: \t" + burpConfigPropertiesFileName);
                System.out.println("2. URLS TO SCAN FILE: \t" + urlsToScanFileName);
                System.out.println("3. RESULT URL FILE: \t" + resultUrlsFileName);

                urlsFromFileToScanReader = new BufferedReader(new FileReader(urlsToScanFileName));

                outurls = new BufferedWriter(new FileWriter(resultUrlsFileName));

                if (burpUnitConfig.getGeneralSettings().getScanQueueCheckInterval().getMilliseconds() != null) {
                    SCAN_QUEUE_CHECK_INTERVALL = burpUnitConfig.getGeneralSettings().getScanQueueCheckInterval().getMilliseconds().intValue();
                    System.out.println("SCAN_QUEUE_CHECK_INTERVALL: \t" + SCAN_QUEUE_CHECK_INTERVALL);
                }

                if (burpUnitConfig.getGeneralSettings().getMaxScanQueueSize().getSize() != null) {
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

    /**
     * Delegate method from BurpExtender. Is called for one time. Provides a
     * callback reference. On the callback the scope gets defined from the
     * loaded url list and the spider is called, both per each url list entry.
     *
     * @param callbacks
     */
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        mcallBacks = callbacks;

        try {
            System.out.println("Loading the following IssueReportWritabeles:");
            issueReportWritableObjectsList = new ArrayList<IssueReportWritable>();
            IssueReportWritable reportWritable;
            for (ReportWriter reportWriterConfig : reportWriterConfigList) {
                System.out.println("- " + reportWriterConfig.getFullQualifiedClassName());
                Class c = Class.forName(reportWriterConfig.getFullQualifiedClassName());
                reportWritable = ((IssueReportWritable) c.newInstance()).initilizeIssueReportWriter(mcallBacks, reportWriterConfig, resultsFileNameSibling);
                issueReportWritableObjectsList.add(reportWritable);
                System.out.println("- " + reportWritable.getOutputFilePath());
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            mcallBacks.exitSuite(false);
        }
        
        overwriteBurpSuiteProperties(mcallBacks, burpUnitConfig.getGeneralSettings().getBurpConfigOverwrites().getProperty());
        startSpidering(urlsFromFileToScanReader);

    }

    /**
     * Overwrites the BurpSuite properties by the given property list.
     * 
     * @param mcallBacks
     * @param propertyList 
     */
    private void overwriteBurpSuiteProperties(final IBurpExtenderCallbacks mcallBacks, final List<Property> propertyList) {
        Map<String, String> configMap = new HashMap();

        System.out.println("\nSetting the following properties:");
        for (Property prop : propertyList) {
            System.out.println("\n" + prop.getName() + ":" + prop.getValue());
            configMap.put(prop.getName(), prop.getValue());
        }
        mcallBacks.loadConfig(configMap);
    }

    /**
     * Starts the spider 
     */   
    private void startSpidering(BufferedReader urlsToScanReader) {
        URL urlFromFile;

        try {
            System.out.println("\nStarting the spider");
            for (String urlStringFromFile; (urlStringFromFile = urlsToScanReader.readLine()) != null;) {
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
            if (Tools.spider.toString().equals(toolName)
                    && !messageIsRequest
                    && mcallBacks.isInScope(messageInfo.getUrl())) {

                if (scanqueue.size() >= MAX_SCAN_QUEUE_SIZE) {
                    maxScanQueueSizeExceeded = true;
                    System.out.println("Max queue size exceeded, blocking all following scan jobs");
                }

                if (!maxScanQueueSizeExceeded) {
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
                                System.out.print(currentItem.getPercentageComplete()+"|");
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
            for (IssueReportWritable issueReportWriterService : issueReportWritableObjectsList) {
                issueReportWriterService.addIssueToReport(issue);
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

            for (IssueReportWritable issueReportWriterService : issueReportWritableObjectsList) {
                issueReportWriterService.closeReport();
            }
            System.out.println("Total time: " + (System.currentTimeMillis() - startMillis));
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
