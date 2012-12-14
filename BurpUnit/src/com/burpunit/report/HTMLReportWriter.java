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
public class HTMLReportWriter implements IssueReportWritable{
    private BufferedWriter outissues;

    @Override
    public void addIssueToReport(IScanIssue issue) {
        try {
            outissues.write("<h1>" + issue.getIssueName() + "</h1>"
                            + "<table>"
                            + "<tr><td><b>Issue:</b></td><td>" + issue.getIssueName() + "</td></tr>"
                            + "<tr><td><b>Severity:</b></td><td>" + issue.getSeverity() + "</td></tr>"
                            + "<tr><td><b>Confidence:</b></td><td>" + issue.getConfidence() + "</td></tr>"
                            + "<tr><td><b>URL:</b></td><td>" + issue.getUrl() + "</td></tr>"
                            + "</table>"
                            + "<h2>Issue Detail</h2>"
                            + "<p>" + issue.getIssueDetail() + "</p>"
                            + "<h2>Issue Background</h2>"
                            + "<p>" + issue.getIssueBackground() + "</p>"
                            + "<h2>Issue Remediation</h2>"   
                            + "<p>" + issue.getRemediationBackground() + "</p>");
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
            outissues = new BufferedWriter(new FileWriter(new File(properties.get(BurpUnit.Properties.RESULT_ISSUES_FILE_NAME.toString())),false));
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }
    
}
