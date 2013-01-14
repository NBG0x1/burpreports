/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.burpunit.report;

import burp.IScanIssue;
import com.burpunit.cfg.BurpUnitConfig.ReportWriter;

/**
 *
 * @author runtz
 */
public interface IssueReportWritable {
    
    public IssueReportWritable initilizeIssueReportWriter(final ReportWriter writerConfig, final String resultsFileNameSibling);
    
    public void addIssueToReport(final IScanIssue issue);
    
    public void closeReport();
    
    public String getOutputFilePath();
    
}
