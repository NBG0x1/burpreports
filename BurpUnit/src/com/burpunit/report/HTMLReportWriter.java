/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.burpunit.report;

import burp.IScanIssue;
import com.burpunit.BurpUnit;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Map;

/**
 *
 * @author runtz
 */
public class HTMLReportWriter implements IssueReportWritable {

    private BufferedWriter outissues;

    @Override
    public void addIssueToReport(IScanIssue issue) {
        try {
            if (!BurpUnit.IssuePriorities.Information.toString().equals(issue.getSeverity())) {
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
            outissues.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    @Override
    public void initilizeIssueReportWriter(Map<String, String> properties) {
        try {
            outissues = new BufferedWriter(new FileWriter(new File(properties.get(BurpUnit.BurpUnitProperties.RESULT_ISSUES_FILE_NAME.toString())), false));
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }
}
