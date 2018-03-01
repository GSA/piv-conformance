package gov.gsa.pivconformance.tools;

import gov.gsa.pivconformance.card.client.*;
import gov.gsa.pivconformance.tlv.*;
import gov.gsa.pivconformance.utils.PCSCUtils;
import gov.gsa.pivconformance.utils.VersionUtils;
import org.apache.commons.cli.*;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.*;
import java.lang.invoke.MethodHandles;
import java.util.Arrays;
import java.util.List;

public class PIVRunner {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(PIVRunner.class);
    private static final Options s_options = new Options();

    static {
        s_options.addOption("a", "all", false, "Scan all readers");
        s_options.addOption("h", "help", false, "Print this help and exit");
    }

    private static void PrintHelpAndExit(int exitCode) {
        new HelpFormatter().printHelp("PIVRunner <options>", s_options);
        System.exit(exitCode);
    }

    public static boolean TestCard(CardHandle c) {
        if(c.isValid()) {
            CardTerminal t = c.getConnectionDescription().getTerminal();
            try {
                if(t.isCardPresent()) {
                    s_logger.info("Card found in reader {}", t.getName());
                } else {
                    s_logger.error("No card was present in reader {}", t.getName());
                    return false;
                }
            } catch (CardException e) {
                s_logger.error("Card communication error", e);
            }
            Card conn = c.getCard();
            s_logger.info("Card connected.");
            s_logger.info("Card protocol: {}", conn.getProtocol());
            s_logger.info("Card ATR: {}", Hex.encodeHexString(conn.getATR().getBytes()));
            ApplicationProperties cardAppProperties = new ApplicationProperties();
            DefaultPIVApplication piv = new DefaultPIVApplication();
            ApplicationAID aid = new ApplicationAID();
            s_logger.info("Attempting to select default PIV application");
            MiddlewareStatus result = piv.pivSelectCardApplication(c, aid, cardAppProperties);
            s_logger.info("pivSelectCardApplication() returned {}", result);
            if(result == MiddlewareStatus.PIV_OK) {
                byte[] pcap = cardAppProperties.getBytes();

                byte [] appID = cardAppProperties.getAppID();
                String appLabel = cardAppProperties.getAppLabel();
                String url = cardAppProperties.getURL();
                List<byte[]> cryptoAlgs = cardAppProperties.getCryptoAlgs();
                byte [] coexistentTagAllocationAuthority = cardAppProperties.getCoexistentTagAllocationAuthority();

                if(appID != null)
                    s_logger.info("Application identifier of application: {}", Hex.encodeHexString(appID));

                if(coexistentTagAllocationAuthority != null)
                    s_logger.info("Coexistent tag allocation authority: {}", Hex.encodeHexString(coexistentTagAllocationAuthority));

                if(appLabel != "")
                    s_logger.info("Application label: {}", appLabel);

                if(url != "")
                    s_logger.info("Uniform resource locator: {}", url);

                if(cryptoAlgs != null) {
                    for(byte[] b : cryptoAlgs) {

                        s_logger.info("Cryptographic algorithms supported:");
                        s_logger.info("Algorithm ID: {} Algorithm Description: {}", Hex.encodeHexString(b), TagConstants.algMAP.get(b));
                    }
                }


                s_logger.info("PCAP: {}", Hex.encodeHexString(pcap));
                BerTlvParser tp = new BerTlvParser(new CCTTlvLogger(PIVRunner.class));
                BerTlv outer = tp.parseConstructed(pcap);
                List<BerTlv> values = outer.getValues();
                for(BerTlv tlv : values) {
                    if(tlv.isPrimitive()) {
                        s_logger.info("PCAP Tag {}: {}", Hex.encodeHexString(tlv.getTag().bytes), Hex.encodeHexString(tlv.getBytesValue()));
                    } else {
                        s_logger.info("PCAP object: {}", Hex.encodeHexString(tlv.getTag().bytes));
                    }
                }
                for(String containerOID : APDUConstants.MandatoryContainers()) {
                    PIVDataObject dataObject = PIVDataObjectFactory.createDataObjectForOid(containerOID);
                    s_logger.info("Attempting to read data object for OID {}", containerOID);
                    result = piv.pivGetData(c, containerOID, dataObject);
                    s_logger.info("pivGetData returned {}", result);
                    if(result != MiddlewareStatus.PIV_OK) break;
                    s_logger.info("Data object bytes: {}", Hex.encodeHexString(dataObject.getBytes()));
                }

            }
            ResponseAPDU rsp = null;
            return true;
        } else {
            s_logger.error("TestCard called with invalid card handle");
        }
        return false;
    }

    public static void main(String[] args) {
        s_logger.info("main class: {}", MethodHandles.lookup().lookupClass().getSimpleName());
        s_logger.info("package version: {}", VersionUtils.GetPackageVersionString());
        s_logger.info("build time: {}", VersionUtils.GetPackageBuildTime());

        CommandLineParser p = new DefaultParser();
        CommandLine cmd = null;
        try {
            cmd = p.parse(s_options, args);
        } catch (ParseException e) {
            s_logger.error("Failed to parse command line arguments", e);
            PrintHelpAndExit(1);
        }

        if(cmd.hasOption("help")) {
            PrintHelpAndExit(0);
        }

        PCSCUtils.ConfigureUserProperties();
        PIVMiddlewareVersion mwv = new PIVMiddlewareVersion();
        MiddlewareStatus middlewareStatus = PIVMiddleware.pivMiddlewareVersion(mwv);
        s_logger.info("pivMiddlewareVersion returned status {} and version {}", middlewareStatus, mwv);

        TerminalFactory tf = TerminalFactory.getDefault();
        List<CardTerminal> terminals = null;
        try {
            terminals = tf.terminals().list();
        } catch (CardException e) {
            s_logger.error("Failed to list card terminals", e);
            System.exit(1);
        }
        if(terminals.size() == 0) {
            s_logger.error("No readers were found.");
            System.exit(1);
        }
        int terminalCount = 0;
        for(CardTerminal t : terminals) {
            terminalCount++;
            ConnectionDescription cd = ConnectionDescription.createFromTerminal(t);
            byte[] descriptor = cd.getBytes();
            if(descriptor != null) {
                s_logger.info("Descriptor for terminal {}: {}", terminalCount, Hex.encodeHexString(descriptor, false));
            }
            // if there is only one reader or if we've been asked to only test one reader,
            // wait for a card
            try {
                if(!t.isCardPresent() && (!cmd.hasOption("all") || terminals.size() == 1)) {
                    s_logger.info("Insert a card into {}", t.getName());
                    t.waitForCardPresent(0);
                }
            } catch (CardException e) {
                s_logger.error("Error checking for card presence", e);
            }
            s_logger.info("Testing with terminal {}: {}", terminalCount, t.getName());
            CardHandle ch = new CardHandle();
            MiddlewareStatus result = PIVMiddleware.pivConnect(true, cd, ch);
            s_logger.info("[{}] PIVMiddleware.pivConnect() returned {} for reader {}", terminalCount, result, t.getName());
            boolean testResult = TestCard(ch);
            if(testResult) {
                s_logger.info("Card test completed successfully.");
            } else {
                s_logger.error("Card test failed.");
            }
            if(!cmd.hasOption("all")) {
                break;
            }
        }

        System.exit(0);

    }
}
