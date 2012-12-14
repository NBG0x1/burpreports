/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.burpunit.report;

import burp.IScanIssue;
import com.burpunit.BurpUnit;
import generated.ObjectFactory;
import generated.Testsuite;
import generated.Testsuite.Properties;
import generated.Testsuite.Properties.Property;
import generated.Testsuite.Testcase;
import generated.Testsuite.Testcase.Failure;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigDecimal;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.Map;
import javax.xml.bind.JAXB;
import javax.xml.datatype.DatatypeFactory;

/**
 *
 * @author runtz
 */
public class XUnitReportWriter implements IssueReportWritable {

    private ObjectFactory oFac;
    private Testsuite testSuite;
    private Failure testCaseFailure;
    private Testcase testCase;
    private BufferedWriter outXUnit;
    private Properties suiteProperties;
    private int numFailures;
    private int numIssues;
    private long millisAtStart;
    private long millisAtEnd;
    private GregorianCalendar gregCal;

    @Override
    public void addIssueToReport(IScanIssue issue) {
        ++numIssues;
        if (!BurpUnit.IssuePriorities.Information.toString().equals(issue.getSeverity())) {
            ++numFailures;
            
            testCaseFailure = oFac.createTestsuiteTestcaseFailure();
            testCaseFailure.setMessage(issue.getIssueName());
            testCaseFailure.setValue("<h2>Issue Detail</h2>"+issue.getIssueDetail()+"<h2>Issue Background</h2>"+issue.getIssueBackground());
            testCaseFailure.setType(issue.getSeverity());
            
            testCase = oFac.createTestsuiteTestcase();
            testCase.setFailure(testCaseFailure);
            testCase.setTime(BigDecimal.valueOf(System.currentTimeMillis()-millisAtStart));
            testCase.setName(issue.getUrl().toString());
            testCase.setClassname("");
            
            testSuite.getTestcase().add(testCase);
        }
    }

    @Override
    public void closeReport() {
        try {
            testSuite.setFailures(numFailures);
            testSuite.setTests(numIssues);
            testSuite.setHostname("diverse, see name at the testcases");
            
            millisAtEnd = System.currentTimeMillis();
            testSuite.setTime(BigDecimal.valueOf(millisAtEnd-millisAtStart));
            gregCal = new GregorianCalendar();
            gregCal.setTimeInMillis(millisAtEnd);
            testSuite.setTimestamp(DatatypeFactory.newInstance().newXMLGregorianCalendar(gregCal));
            
            testSuite.setName("BurpSuite Test");
            testSuite.setSystemOut("");
            testSuite.setSystemErr("");
            
            JAXB.marshal(testSuite, outXUnit);
            outXUnit.close();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    @Override
    public void initilizeIssueReportWriter(Map<String, String> properties) {
        millisAtStart = System.currentTimeMillis();
                
        oFac = new ObjectFactory();
        testSuite = oFac.createTestsuite();
        suiteProperties = oFac.createTestsuiteProperties();

        testSuite.setProperties(suiteProperties);

        try {
            outXUnit = new BufferedWriter(new FileWriter(new File(properties.get(BurpUnit.Properties.RESULT_XUNIT_FILE_NAME.toString())), false));
        } catch (IOException ex) {
            ex.printStackTrace();
        }

        Iterator<String> keyIt = properties.keySet().iterator();
        String curKey;
        Property curProp;

        while (keyIt.hasNext()) {
            curKey = keyIt.next();
            // i need a fluent interface miau
            curProp = oFac.createTestsuitePropertiesProperty();
            curProp.setName(curKey);
            curProp.setValue(properties.get(curKey));
            testSuite.getProperties().getProperty().add(curProp);
        }



    }
}
