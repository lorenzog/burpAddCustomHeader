package burp;

import javax.swing.SwingUtilities;
import java.awt.Component;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class BurpExtender implements IBurpExtender, ISessionHandlingAction, ITab, IExtensionStateListener {

    IExtensionHelpers helpers = null;
    Pattern p;

    static String extensionName = "Add Custom Header";
    IBurpExtenderCallbacks callbacks = null;

    // some default values
    final String DEFAULT_HEADER_NAME = "Authorization";
    final String DEFAULT_HEADER_VALUE_PREFIX = "Bearer ";
    final String DEFAULT_REGEXP = "access_token\":\"(.*?)\"";
    final String DEFAULT_HARDCODED_VALUE = "<insert static JWT token here>";

    //storage key for settings
    final String KEY_REGEX = "setting_regex";
    final String KEY_HARDCODED_VALUE = "setting_hardcoded_value";
    final String KEY_MODE = "setting_mode";
    final String KEY_HEADER_NAME = "settings_header_name";
    final String KEY_HEADER_VALUE_PREFIX = "settings_header_value_prefix";

    private BurpTab tab;

    void useRegExp() {

    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName(extensionName);
        this.helpers = callbacks.getHelpers();
        callbacks.registerSessionHandlingAction(this);
        //Register the listener to trigger the auto storage of the settings
        callbacks.registerExtensionStateListener(this);

        // create our UI
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                tab = new BurpTab();

                // set some default values
                tab.setHeaderName(DEFAULT_HEADER_NAME);
                tab.setHeaderValuePrefix(DEFAULT_HEADER_VALUE_PREFIX);
                tab.setRegExpText(DEFAULT_REGEXP);
                tab.setHardCodedText(DEFAULT_HARDCODED_VALUE);

                //Loaded stored settings (if exists)
                String headerName = callbacks.loadExtensionSetting(KEY_HEADER_NAME);
                if(headerName != null && headerName.trim().length() > 0){
                    tab.setHeaderName(headerName);
                }
                String headerValuePrefix = callbacks.loadExtensionSetting(KEY_HEADER_VALUE_PREFIX);
                if(headerValuePrefix != null && headerValuePrefix.trim().length() > 0){
                    tab.setHeaderValuePrefix(headerValuePrefix);
                }
                String regex = callbacks.loadExtensionSetting(KEY_REGEX);
                if(regex != null && regex.trim().length() > 0){
                    tab.setRegExpText(regex);
                }
                String hardCodedText = callbacks.loadExtensionSetting(KEY_HARDCODED_VALUE);
                if(hardCodedText != null && hardCodedText.trim().length() > 0){
                    tab.setHardCodedText(hardCodedText);
                }
                String mode = callbacks.loadExtensionSetting(KEY_MODE);
                if("REGEX".equalsIgnoreCase(mode)){
                    tab.setUseRegExp();
                }else if("HARD_CODED".equalsIgnoreCase(mode)){
                    tab.setUseHardCoded();
                }
                callbacks.printOutput("Mode loaded: " + mode);

                // force update the example label
                tab.updateFinalResultLabel();
                // customize our UI components
                callbacks.customizeUiComponent(tab);
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });

        callbacks.printOutput("Add Header Extension loaded");
    }

    // methods below from ISessionHandlingAction
    @Override
    public String getActionName() {
        return extensionName;
    }

    @Override
    public void performAction(IHttpRequestResponse currentRequest,
            IHttpRequestResponse[] macroItems) {

        String token = null;

        if (tab.useHardCoded()) {
            // token has priority over regexp
            token = tab.getHardCodedText();
        } else if (tab.useRegExp()) {
            if (macroItems.length == 0) {
                this.callbacks.issueAlert("No macro configured or macro did not return any response");
                return;
            }
            String regexp = tab.getRegExpText();
            try {
                p = Pattern.compile(regexp);
            } catch (PatternSyntaxException e) {
                this.callbacks.issueAlert("Syntax error in regular expression (see extension error window)");
                callbacks.printError(e.toString());
                return;
            }

            // go through all macros and run the regular expression on their body
            for (int i = 0; i < macroItems.length; i++) {
                byte[] _responseBody = macroItems[i].getResponse();
                if (_responseBody == null) return;
                IResponseInfo macroResponse = helpers.analyzeResponse(_responseBody);
                if (macroResponse == null ) return;
                String responseBody = helpers.bytesToString(_responseBody);
                Matcher m = p.matcher(responseBody);
                if (m.find()) {
                    token = m.group(1);
                    if (token != null && token.length() > 0) {
                        // found it
                        break;
                    }
                }
            }
        } else {
            // using the 'disable' button
            return;
        }

        if (token == null) {
            // nothing found: failing silently to avoid polluting the logs
            callbacks.printError("No token found");
            return;
        }

        String headerName = tab.getHeaderName();
        String headerValuePrefix = tab.getHeaderValuePrefix();
        
        IRequestInfo rqInfo = helpers.analyzeRequest(currentRequest);
        // retrieve all headers
        ArrayList<String> headers = (ArrayList<String>) rqInfo.getHeaders();
        for (int i = 0; i < headers.size(); i++) {
            if (((String) headers.get(i)).startsWith(headerName + ": " + headerValuePrefix)) {
                // there could be more than one header like this; remove and continue
                headers.remove(i);
            }
        }
        String newHeader = headerName + ": " + headerValuePrefix + token;
        headers.add(newHeader);
        callbacks.printOutput("Added header: '" + newHeader + "'");

        byte[] message = helpers.buildHttpMessage(headers, Arrays.copyOfRange(currentRequest.getRequest(), rqInfo.getBodyOffset(), currentRequest.getRequest().length));
        currentRequest.setRequest(message);
    }
    // end ISessionHandlingAction methods

    // ITab methods
    @Override
    public String getTabCaption() {
        return extensionName;
    }

    @Override
    public Component getUiComponent() {
        return tab;
    }

    @Override
    public void extensionUnloaded() {
        //Save settings when burp close and extension is unloaded
        callbacks.printOutput("Saving settings to project file...");
        callbacks.saveExtensionSetting(KEY_HEADER_NAME, tab.getHeaderName());
        callbacks.saveExtensionSetting(KEY_HEADER_VALUE_PREFIX, tab.getHeaderValuePrefix());
        callbacks.saveExtensionSetting(KEY_REGEX, tab.getRegExpText());
        callbacks.saveExtensionSetting(KEY_HARDCODED_VALUE, tab.getHardCodedText());
        String mode = "DISABLED";
        if(tab.useHardCoded()){
            mode = "HARD_CODED";
        }else if(tab.useRegExp()){
            mode = "REGEX";
        }
        callbacks.saveExtensionSetting(KEY_MODE, mode);
        callbacks.printOutput("Settings saved!");
    }
    // end ITab methods

}
