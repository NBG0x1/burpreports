
import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import com.burpunit.BurpUnitizer;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author runtz
 */
public class BurpExtender implements IBurpExtender {

    private BurpUnitizer bsp = new BurpUnitizer();

    @Override
    public void setCommandLineArgs(String[] args) {
        bsp.setCommandLineArgs(args);
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        bsp.registerExtenderCallbacks(callbacks);
    }

    @Override
    public void processHttpMessage(String toolName, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        bsp.processHttpMessage(toolName, messageIsRequest, messageInfo);
    }

    @Override
    public void newScanIssue(IScanIssue issue) {
        bsp.newScanIssue(issue);
    }

    @Override
    public void applicationClosing() {
        bsp.applicationClosing();
    }

    @Override
    public byte[] processProxyMessage(int messageReference, boolean messageIsRequest, String remoteHost, int remotePort, boolean serviceIsHttps, String httpMethod, String url, String resourceType, String statusCode, String responseContentType, byte[] message, int[] action) {
        return new byte[0];
    }
}
