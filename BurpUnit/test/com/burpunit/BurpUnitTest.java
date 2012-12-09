/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.burpunit;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author runtz
 */
public class BurpUnitTest {
    
    public BurpUnitTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test of setCommandLineArgs method, of class BurpUnit.
     */
    @Test
    public void testSetCommandLineArgs() {
        System.out.println("setCommandLineArgs");
        String[] args = null;
        BurpUnit instance = new BurpUnit();
        instance.setCommandLineArgs(args);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of registerExtenderCallbacks method, of class BurpUnit.
     */
    @Test
    public void testRegisterExtenderCallbacks() {
        System.out.println("registerExtenderCallbacks");
        IBurpExtenderCallbacks callbacks = null;
        BurpUnit instance = new BurpUnit();
        instance.registerExtenderCallbacks(callbacks);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of processHttpMessage method, of class BurpUnit.
     */
    @Test
    public void testProcessHttpMessage() {
        System.out.println("processHttpMessage");
        String toolName = "";
        boolean messageIsRequest = false;
        IHttpRequestResponse messageInfo = null;
        BurpUnit instance = new BurpUnit();
        instance.processHttpMessage(toolName, messageIsRequest, messageInfo);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of newScanIssue method, of class BurpUnit.
     */
    @Test
    public void testNewScanIssue() {
        System.out.println("newScanIssue");
        IScanIssue issue = null;
        BurpUnit instance = new BurpUnit();
        instance.newScanIssue(issue);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of applicationClosing method, of class BurpUnit.
     */
    @Test
    public void testApplicationClosing() {
        System.out.println("applicationClosing");
        BurpUnit instance = new BurpUnit();
        instance.applicationClosing();
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }
}
