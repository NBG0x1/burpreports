import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import com.burpunit.BurpUnit;

/*
 * BurpExtender delegate
 */
/**
 *
 * @author runtz
 */
public class BurpExtender implements IBurpExtender {

    private BurpUnit burpUnit = new BurpUnit();

    @Override
    public void setCommandLineArgs(String[] args) {
        burpUnit.setCommandLineArgs(args);
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        burpUnit.registerExtenderCallbacks(callbacks);
    }

    @Override
    public void processHttpMessage(String toolName, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        burpUnit.processHttpMessage(toolName, messageIsRequest, messageInfo);
    }

    @Override
    public void newScanIssue(IScanIssue issue) {
        burpUnit.newScanIssue(issue);
    }

    @Override
    public void applicationClosing() {
        burpUnit.applicationClosing();
    }

    @Override
    public byte[] processProxyMessage(int messageReference, boolean messageIsRequest, String remoteHost, int remotePort, boolean serviceIsHttps, String httpMethod, String url, String resourceType, String statusCode, String responseContentType, byte[] message, int[] action) {
        return new byte[0];
    }
}
