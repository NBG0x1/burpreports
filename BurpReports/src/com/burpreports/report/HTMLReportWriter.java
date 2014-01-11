/*
 * Writes the scan results as html into a file.
 */
package com.burpreports.report;

import burp.IBurpExtenderCallbacks;
import burp.IScanIssue;
import com.burpreports.cfg.BurpReportsConfig.ReportWriter;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

/**
 * HTMLReport Writer to write html scan reports
 * 
 * @author runtz
 */
public class HTMLReportWriter implements IssueReportWritable {

    private BufferedWriter outissues;
    private String outputFilePath;
    private static final String HTML_REPORT_FILE_POSTFIX = ".html";
    private String issuePriorityToStartWriting;

    @Override
    public void addIssueToReport(final IScanIssue issue) {
        try {
            if (IssuePriority.valueOf(issuePriorityToStartWriting.toUpperCase()).getValue()
                <= IssuePriority.valueOf(issue.getSeverity().toUpperCase()).getValue()) {
                outissues.write("<h1>" + issue.getIssueName() + "</h1>\r\n"
                        + "<table>\r\n"
                        + "<tr><td><b>Issue:</b></td><td>" + issue.getIssueName() + "</td></tr>\r\n"
                        + "<tr><td><b>Severity:</b></td><td>" + issue.getSeverity() + "</td></tr>\r\n"
                        + "<tr><td><b>Confidence:</b></td><td>" + issue.getConfidence() + "</td></tr>\r\n"
                        + "<tr><td><b>URL:</b></td><td>" + issue.getUrl() + "</td></tr>\r\n"
                        + "</table>\r\n"
                        + "<h2>Issue Detail</h2>\r\n"
                        + "<p>" + issue.getIssueDetail() + "</p>\r\n"
                        + "<h2>Issue Background</h2>\r\n"
                        + "<p>" + issue.getIssueBackground() + "</p>\r\n"
                        + "<h2>Issue Remediation</h2>\r\n"
                        + "<p>" + issue.getRemediationBackground() + "</p>\r\n");
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    @Override
    public void closeReport() {
        try {
            if(outissues != null) {
                outissues.close();
            } else {
                System.out.append("Nothing to close.");
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    @Override
    public IssueReportWritable initilizeIssueReportWriter(final IBurpExtenderCallbacks callback, final ReportWriter writerConfig, final String resultsFileNameSibling) {
        try {
            outputFilePath = writerConfig.getOutputFilepath().getPath() + resultsFileNameSibling + HTML_REPORT_FILE_POSTFIX;
            issuePriorityToStartWriting = writerConfig.getIssuePriorityToStartWriting().getPrio();
            
            outissues = new BufferedWriter(new FileWriter(new File(outputFilePath), false));
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        
        return this;
    }

    @Override
    public String getOutputFilePath() {
        return (outputFilePath != null)?outputFilePath:"";
    }
}
