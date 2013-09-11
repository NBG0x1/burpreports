/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.burpreports.report;

import burp.IBurpExtenderCallbacks;
import burp.IScanIssue;
import com.burpreports.cfg.BurpReportsConfig.ReportWriter;
import java.io.File;

/**
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
    public IssueReportWritable initilizeIssueReportWriter(IBurpExtenderCallbacks callback, ReportWriter writerConfig, String resultsFileNameSibling) {
        mcallBacks = callback;
        resultBurpFileName = writerConfig.getOutputFilepath().getPath() + resultsFileNameSibling + RESULT_BURP_FILE_POSTFIX;
        outsession = new File(resultBurpFileName);
        issuePriorityToStartWriting = writerConfig.getIssuePriorityToStartWriting().getPrio();
        return this;
    }

    @Override
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
    public void closeReport() {
        // nothing to close
    }

    @Override
    public String getOutputFilePath() {
        return (resultBurpFileName != null) ? resultBurpFileName : "";
    }
}
