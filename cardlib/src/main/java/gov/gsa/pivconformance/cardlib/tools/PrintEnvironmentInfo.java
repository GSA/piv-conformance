package gov.gsa.pivconformance.cardlib.tools;

import gov.gsa.pivconformance.cardlib.utils.PCSCUtils;
import gov.gsa.pivconformance.cardlib.utils.VersionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import java.lang.invoke.MethodHandles;
import java.security.Provider;
import java.security.Security;

public class PrintEnvironmentInfo {

    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(PrintEnvironmentInfo.class);

    /**
     * A simple test program that dumps info about the environment we're running in.
     */
    public static void main(String[] args) {
        s_logger.info("main class: {}", MethodHandles.lookup().lookupClass().getSimpleName());
        s_logger.info("package version: {}", VersionUtils.GetPackageVersionString());
        s_logger.info("build time: {}", VersionUtils.GetPackageBuildTime());
        PCSCUtils.ConfigureUserProperties();
        s_logger.info("System properties");
        System.getProperties().forEach((key, value) -> s_logger.info("property: '{}' = '{}'", key, value));
        for (Provider prov : Security.getProviders()) {
            s_logger.info("Security Provider: {} version {}", prov.getName(), prov.getVersion());
        }
        TerminalFactory tf = TerminalFactory.getDefault();
        s_logger.info("Attempting to list card terminals");
        try {
            for (CardTerminal t : tf.terminals().list()) {
                s_logger.info("Reader: {}: {}", t.getName(), t.isCardPresent() ? "Card present":"Card not present");
            }
        } catch (CardException e) {
            s_logger.error("Unable to enumerate card terminals", e);
        }
    }
}

