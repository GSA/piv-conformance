package gov.gsa.conformancelib.pivconformancetools;

import gov.gsa.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.conformancelib.configuration.ConformanceTestDatabase;
import gov.gsa.conformancelib.configuration.TestCaseModel;
import gov.gsa.conformancelib.junitoptions.Theme;
import gov.gsa.conformancelib.tests.SignedObjectVerificationTests;
import gov.gsa.pivconformance.utils.PCSCUtils;
import gov.gsa.pivconformance.utils.VersionUtils;
import gov.gsa.conformancelib.pivconformancetools.junitconsole.VerboseTreePrintingListener;
import org.apache.commons.cli.*;
import org.junit.platform.engine.DiscoverySelector;
import org.junit.platform.launcher.*;
//import org.junit.platform;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;
import org.junit.platform.launcher.listeners.TestExecutionSummary;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Method;
import java.nio.charset.Charset;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectMethod;

public class ConformanceTestRunner {

    private static final String FIRST_CONFIG = "SELECT * from SystemSettings LIMIT 1";
    private static final String NAMED_CONFIG = "SELECT * from SystemSettings where SettingsGroup='?'";
    private static final String TEST_SET = "SELECT * from TestCases where Enabled=1";

    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(ConformanceTestRunner.class);
    private static final Options s_options = new Options();
    static {
        s_options.addOption("h", "help", false, "Print this help and exit");
        s_options.addOption("c", "config", true, "path to config file");
        s_options.addOption("n", "configName", true, "group of system settings to use if the config database has more than one");
    }
    private static void PrintHelpAndExit(int exitCode) {
        new HelpFormatter().printHelp("ConfigGenerator <options>", s_options);
        System.exit(exitCode);
    }
    public static void main(String[] args) {
        s_logger.info("main class: {}", MethodHandles.lookup().lookupClass().getSimpleName());
        s_logger.info("package version: {}", VersionUtils.GetPackageVersionString());
        PCSCUtils.ConfigureUserProperties();
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

        Connection conn = null;
        if(cmd.hasOption("config")) {
            String dbParam = cmd.getOptionValue("config");
            File f = new File(dbParam);
            if (!f.exists()) {
                s_logger.error("No such file: {}", dbParam);
                System.exit(1);
            }

            String dbUrl = null;
            try {
                dbUrl = "jdbc:sqlite:" + f.getCanonicalPath();
            } catch (IOException e) {
                s_logger.error("Unable to calculate canonical name for database file", e);
                System.exit(1);
            }
            try {
                conn = DriverManager.getConnection(dbUrl);
            } catch (SQLException e) {
                s_logger.error("Unable to establish JDBC connection for SQLite database", e);
                System.exit(1);
            }
            if (conn != null) {
                s_logger.debug("Created sql connection for {}", dbParam);
                DatabaseMetaData metaData = null;
                try {
                    metaData = conn.getMetaData();
                    s_logger.debug("Driver: {} version {}", metaData.getDriverName(), metaData.getDriverVersion());
                } catch (SQLException e) {
                    s_logger.error("Unable to read driver metadata", e);
                }
            }
            s_logger.info("Opened configuration in {}", dbParam);
        }

        CardSettingsSingleton css = CardSettingsSingleton.getInstance();

 
        System.out.println("--------------------------------------------------------------");
        TestExecutionSummary summary = summaryListener.getSummary();
        List<TestExecutionSummary.Failure> failures = summary.getFailures();
        for(TestExecutionSummary.Failure f : failures) {
            TestIdentifier ti = f.getTestIdentifier();
            System.out.println(String.format("Test failure: {}", ti.getDisplayName()));
        }
        summary.printTo(new PrintWriter(System.out));

    }
    private static SummaryGeneratingListener registerListeners(PrintWriter out, Launcher launcher) {
        SummaryGeneratingListener summaryListener = new SummaryGeneratingListener();
        launcher.registerTestExecutionListeners(summaryListener);
        launcher.registerTestExecutionListeners(createDetailsPrintingListener(out));
        return summaryListener;
    }

    private static TestExecutionListener createDetailsPrintingListener(PrintWriter out) {
        boolean disableAnsiColors = false;//options.isAnsiColorOutputDisabled();
        Theme theme = Theme.valueOf(Charset.defaultCharset());//options.getTheme();
        return new gov.gsa.conformancelib.pivconformancetools.junitconsole.VerboseTreePrintingListener(out, disableAnsiColors, 16, theme);
    }
}
