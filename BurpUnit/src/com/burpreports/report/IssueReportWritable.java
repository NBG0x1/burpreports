/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.burpreports.report;

import burp.IBurpExtenderCallbacks;
import burp.IScanIssue;
import com.burpreports.cfg.BurpReportsConfig.ReportWriter;

/**
 *
 * @author runtz
 */
public interface IssueReportWritable {
    
    public IssueReportWritable initilizeIssueReportWriter(final IBurpExtenderCallbacks callback, final ReportWriter writerConfig, final String resultsFileNameSibling);
    
    public void addIssueToReport(final IScanIssue issue);
    
    public void closeReport();
    
    public String getOutputFilePath();
    
}
