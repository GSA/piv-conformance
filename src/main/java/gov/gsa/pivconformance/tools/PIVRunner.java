package gov.gsa.pivconformance.tools;

import gov.gsa.pivconformance.card.client.*;
import gov.gsa.pivconformance.utils.PCSCUtils;
import gov.gsa.pivconformance.utils.VersionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import java.lang.invoke.MethodHandles;
import java.util.List;

public class PIVRunner {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(PIVRunner.class);

    public static void main(String[] args) {
        s_logger.info("main class: {}", MethodHandles.lookup().lookupClass().getSimpleName());
        s_logger.info("package version: {}", VersionUtils.GetPackageVersionString());
        s_logger.info("build time: {}", VersionUtils.GetPackageBuildTime());

        PIVMiddlewareVersion mwv = new PIVMiddlewareVersion();
        MiddlewareStatus middlewareStatus = PIVMiddleware.pivMiddlewareVersion(mwv);
        s_logger.info("pivMiddlewareVersion returned status {} and version {}", middlewareStatus, mwv);

        TerminalFactory tf = TerminalFactory.getDefault();
        CardTerminal firstTerminal = null;
        try {
            List<CardTerminal> terminals = tf.terminals().list();
            firstTerminal = terminals.get(0);
        } catch (CardException e) {
            s_logger.error("Failed to list card terminals", e);
        }
        CardHandle ch = new CardHandle();
        ConnectionDescription cd = ConnectionDescription.createFromTerminal(firstTerminal);
        s_logger.info("Testing with terminal {}", firstTerminal.getName());

        MiddlewareStatus result = PIVMiddleware.pivConnect(true, cd, ch);

        s_logger.info("pivConnect returned {} for reader {}", result, firstTerminal.getName());

//        PCSCUtils.ConfigureUserProperties();
//        try {
//
//            TerminalFactory tf2 = TerminalFactory.getDefault();
//            s_logger.info("Attempting to list card terminals");
//            try {
//                for (CardTerminal t : tf2.terminals().list()) {
//                    s_logger.info("Reader: {}: {}", t.getName(), t.isCardPresent() ? "Card present":"Card not present");
//
//                    ConnectionDescription connectionDescription = ConnectionDescription.createFromTerminal(t);
//
//                    byte [] connectionDescriptionBuffer = connectionDescription.getBytes();
//
//                    s_logger.info("ConnectionDescription: {}", org.apache.commons.codec.binary.Hex.encodeHexString(connectionDescriptionBuffer));
//                }
//            } catch (CardException e) {
//                s_logger.error("Unable to enumerate card terminals", e);
//            }
//
//
//
//        }catch (Exception ex) {
//
//            s_logger.info("Exception : {}", ex.getMessage());
//        }

    }
}
