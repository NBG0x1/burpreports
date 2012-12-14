/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.burpunit.report;

import burp.IScanIssue;
import java.util.Map;

/**
 *
 * @author runtz
 */
public interface IssueReportWritable {
    
    public void initilizeIssueReportWriter(Map<String,String> properties);
    
    public void addIssueToReport(IScanIssue issue);
    
    public void closeReport();
    
}
