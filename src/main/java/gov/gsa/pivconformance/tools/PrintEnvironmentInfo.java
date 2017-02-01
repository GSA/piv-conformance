package gov.gsa.pivconformance.tools;

import gov.gsa.pivconformance.utils.VersionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
        s_logger.info("System properties");
        System.getProperties().forEach((key, value) -> s_logger.info("property: '{}' = '{}'", key, value));
        for (Provider prov : Security.getProviders()) {
            s_logger.info("Security Provider: {} version {}", prov.getName(), prov.getVersion());
        }
    }
}

