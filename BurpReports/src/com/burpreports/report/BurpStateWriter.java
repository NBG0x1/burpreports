/*
 * Writes the Burp Suite state into an file. The State could be loaded afterwards 
 * into the Burp Suite to restore the state for looking up all scanned urls, reports, 
 * settings etc.
 */
package com.burpreports.report;

import burp.IBurpExtenderCallbacks;
import burp.IScanIssue;
import com.burpreports.cfg.BurpReportsConfig.ReportWriter;
import java.io.File;

/**
 * State Writer to write the Burp Suite state to file.
 * 
 * @author runtz
 */
public class BurpStateWriter implements IssueReportWritable {

    private static final String RESULT_BURP_FILE_POSTFIX = ".burp";
    private String resultBurpFileName;
    private IBurpExtenderCallbacks mcallBacks;
    private File outsession;
    private String issuePriorityToStartWriting;

    @Override
    /**
     * Reads the file path, creates a file handle, reads the prio setting 
     * defining with issues should saved of the issues found
     */
    public IssueReportWritable initilizeIssueReportWriter(IBurpExtenderCallbacks callback, ReportWriter writerConfig, String resultsFileNameSibling) {
        mcallBacks = callback;
        resultBurpFileName = writerConfig.getOutputFilepath().getPath() + resultsFileNameSibling + RESULT_BURP_FILE_POSTFIX;
        outsession = new File(resultBurpFileName);
        issuePriorityToStartWriting = writerConfig.getIssuePriorityToStartWriting().getPrio();
        return this;
    }

    @Override
    /**
     * Saves the Burp Suite state if issues appeared with the the same or higher
     * prio defined within the config.
     */
    public void addIssueToReport(IScanIssue issue) {
        if (IssuePriority.valueOf(issuePriorityToStartWriting.toUpperCase()).getValue()
                <= IssuePriority.valueOf(issue.getSeverity().toUpperCase()).getValue()) {
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
    }

    @Override
    /**
     * Nothing to close
     */
    public void closeReport() {
    }

    @Override
    /**
     * Returns the output file path
     */
    public String getOutputFilePath() {
        return (resultBurpFileName != null) ? resultBurpFileName : "";
    }
}
