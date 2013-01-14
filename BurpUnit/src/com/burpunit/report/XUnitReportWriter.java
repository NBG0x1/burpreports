/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.burpunit.report;

import burp.IScanIssue;
import com.burpunit.cfg.BurpUnitConfig.ReportWriter;
import com.burpunit.report.Testsuite.Properties;
import com.burpunit.report.Testsuite.Properties.Property;
import com.burpunit.report.Testsuite.Testcase;
import com.burpunit.report.Testsuite.Testcase.Failure;
import java.io.File;
import java.io.FileOutputStream;
import java.math.BigDecimal;
import java.util.GregorianCalendar;
import javax.xml.bind.JAXB;
import javax.xml.datatype.DatatypeFactory;

/**
 *
 * @author runtz
 */
public class XUnitReportWriter implements IssueReportWritable {
    
    private static final String XUNIT_REPORT_FILE_POSTFIX = ".xml";

    private ObjectFactory oFac;
    private Testsuite testSuite;
    private Failure testCaseFailure;
    private Testcase testCase;
    private FileOutputStream outXUnit;
    private Properties suiteProperties;
    private int numFailures;
    private int numIssues;
    private long millisAtStart;
    private long millisAtEnd;
    private GregorianCalendar gregCal;
    private String outputFilePath;
    private String issuePriorityToStartWriting;

    @Override
    public void addIssueToReport(final IScanIssue issue) {
        ++numIssues;
        if (!issuePriorityToStartWriting.equals(issue.getSeverity())) {
            try {
                ++numFailures;

                testCaseFailure = oFac.createTestsuiteTestcaseFailure();
                testCaseFailure.setMessage(issue.getIssueName());
                testCaseFailure.setValue("<h2>Issue Detail</h2>" + issue.getIssueDetail() + "<h2>Issue Background</h2>" + issue.getIssueBackground());
                testCaseFailure.setType(issue.getSeverity());

                testCase = oFac.createTestsuiteTestcase();
                testCase.setFailure(testCaseFailure);
                testCase.setTime(BigDecimal.valueOf(System.currentTimeMillis() - millisAtStart));
                testCase.setName(issue.getUrl().toString());
                testCase.setClassname("");

                testSuite.getTestcase().add(testCase);

                deleteAndCreateFile(outputFilePath);
                JAXB.marshal(testSuite, outXUnit);
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }

    private void deleteAndCreateFile(final String fileName) {
        try {
            outXUnit = new FileOutputStream(new File(fileName));
        } catch (Exception ex) {
            ex.printStackTrace();
        }

    }

    @Override
    public void closeReport() {
        try {
            testSuite.setFailures(numFailures);
            testSuite.setTests(numIssues);
            testSuite.setHostname("diverse, see name at the testcases");

            millisAtEnd = System.currentTimeMillis();
            testSuite.setTime(BigDecimal.valueOf(millisAtEnd - millisAtStart));
            gregCal = new GregorianCalendar();
            gregCal.setTimeInMillis(millisAtEnd);
            testSuite.setTimestamp(DatatypeFactory.newInstance().newXMLGregorianCalendar(gregCal));

            testSuite.setName("BurpSuite Test");
            testSuite.setSystemOut("");
            testSuite.setSystemErr("");

            deleteAndCreateFile(outputFilePath);
            JAXB.marshal(testSuite, outXUnit);
            outXUnit.close();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    @Override
    public IssueReportWritable initilizeIssueReportWriter(final ReportWriter writerConfig, final String resultsFileNameSibling) {       
        millisAtStart = System.currentTimeMillis();

        outputFilePath = writerConfig.getOutputFilepath().getPath()+resultsFileNameSibling+XUNIT_REPORT_FILE_POSTFIX;
        issuePriorityToStartWriting = writerConfig.getIssuePriorityToStartWriting().getPrio();
        
        oFac = new ObjectFactory();
        testSuite = oFac.createTestsuite();
        suiteProperties = oFac.createTestsuiteProperties();

        testSuite.setProperties(suiteProperties);
        
        deleteAndCreateFile(outputFilePath);

        Property curProp = oFac.createTestsuitePropertiesProperty();
        curProp.setName("IssuePriorityToStartWriting");
        curProp.setValue(issuePriorityToStartWriting);
        testSuite.getProperties().getProperty().add(curProp);
        
        return this;
    }

    @Override
    public String getOutputFilePath() {
        return (outputFilePath!=null)?outputFilePath:"";
    }
}
