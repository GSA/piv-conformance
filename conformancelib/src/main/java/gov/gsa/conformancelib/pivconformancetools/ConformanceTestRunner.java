package gov.gsa.conformancelib.pivconformancetools;

import gov.gsa.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.conformancelib.configuration.ConformanceTestDatabase;
import gov.gsa.conformancelib.configuration.TestCaseModel;
import gov.gsa.conformancelib.junitoptions.Theme;
import gov.gsa.conformancelib.tests.SignedObjectVerificationTests;
import gov.gsa.pivconformance.card.client.APDUConstants;
import gov.gsa.pivconformance.card.client.CardCapabilityContainer;
import gov.gsa.pivconformance.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.card.client.PIVDataObjectFactory;
import gov.gsa.pivconformance.utils.PCSCUtils;
import gov.gsa.pivconformance.utils.VersionUtils;
import gov.gsa.conformancelib.pivconformancetools.junitconsole.VerboseTreePrintingListener;
import org.apache.commons.cli.*;
import org.apache.commons.codec.binary.Hex;
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

        try (Statement configStatement = conn.createStatement()) {
            ResultSet rs = configStatement.executeQuery(FIRST_CONFIG);
            rs.next();
            String readerName = rs.getString("ReaderName");
            if(readerName == null || readerName.isEmpty()) {
                s_logger.info("No reader was specified. Using the first available reader.");
                css.setReaderIndex(0);
            } else {
                int curr = -1;
                int found = curr;
                List<String> readers = PCSCUtils.GetConnectedReaders();
                for(String reader : readers) {
                    curr++;
                    if(reader.toUpperCase().startsWith(readerName.toUpperCase())) {
                        s_logger.info("Found reader matching {} from configuration", curr);
                        found = curr;
                        break;
                    }
                }
                if(found == -1) {
                    s_logger.warn("No reader matching {} is connected to the system. Using the first reader available.", readerName);
                    css.setReaderIndex(0);
                } else {
                    css.setReaderIndex(found);
                }
                String pinFromConfig = rs.getString("ApplicationPIN");
                if(pinFromConfig != null && !pinFromConfig.isEmpty()) {
                    css.setApplicationPin(pinFromConfig);
                } else {
                    css.setApplicationPin("123456");
                }
                
                for(String containerOID : APDUConstants.MandatoryContainers()) {
                    PIVDataObject dataObject = PIVDataObjectFactory.createDataObjectForOid(containerOID);
                    s_logger.info("Attempting to read data object for OID {} ({})", containerOID, APDUConstants.oidNameMAP.get(containerOID));
                    MiddlewareStatus result = css.getPivHandle().pivGetData(css.getCardHandle(), containerOID, dataObject);
                    if(result != MiddlewareStatus.PIV_OK) continue;
                    boolean decoded = dataObject.decode();
                    s_logger.info("{} {}", dataObject.getFriendlyName(), decoded ? "decoded successfully" : "failed to decode");
                    s_logger.info("pivGetData returned {}", result);
                    s_logger.info(dataObject.toString());

                    if(containerOID.equals(APDUConstants.CARD_CAPABILITY_CONTAINER_OID)) {

                        s_logger.info("Card Identifier: {}", Hex.encodeHexString(((CardCapabilityContainer) dataObject).getCardIdentifier()));
                        s_logger.info("Capability Container Version Number: {}", Hex.encodeHexString(((CardCapabilityContainer) dataObject).getCapabilityContainerVersionNumber()));
                        s_logger.info("Capability Grammar Version Number: {}", Hex.encodeHexString(((CardCapabilityContainer) dataObject).getCapabilityGrammarVersionNumber()));

                        List<byte[]> appCardURLList = ((CardCapabilityContainer) dataObject).getAppCardURL();

                        if (appCardURLList.size() > 0) {
                            s_logger.info("Applications CardURL List");
                            for (byte[] u : appCardURLList) {
                                s_logger.info("{}", Hex.encodeHexString(u));
                            }
                        }


                        s_logger.info("Registered Data Model number: {}", Hex.encodeHexString(((CardCapabilityContainer) dataObject).getRegisteredDataModelNumber()));
                        s_logger.info("Access Control Rule Table: {}", Hex.encodeHexString(((CardCapabilityContainer) dataObject).getAccessControlRuleTable()));


                        s_logger.info("Card APDUs Tag Present: {}", ((CardCapabilityContainer) dataObject).getCardAPDUs());
                        s_logger.info("RedirectionTag Tag Present: {}", ((CardCapabilityContainer) dataObject).getRedirectionTag());
                        s_logger.info("Capability Tuples Tag Present: {}", ((CardCapabilityContainer) dataObject).getCapabilityTuples());
                        s_logger.info("Status Tuples Tag Present: {}", ((CardCapabilityContainer) dataObject).getStatusTuples());
                        s_logger.info("Next CCC Tag Present: {}", ((CardCapabilityContainer) dataObject).getNextCCC());

                        if (((CardCapabilityContainer) dataObject).getExtendedApplicationCardURL() != null) {

                            List<byte[]> extendedAppCardURLList = ((CardCapabilityContainer) dataObject).getExtendedApplicationCardURL();

                            if (extendedAppCardURLList.size() > 0) {
                                s_logger.info("Extended Application CardURL List:");
                                for (byte[] u2 : extendedAppCardURLList) {
                                    s_logger.info("     {}", Hex.encodeHexString(u2));
                                }
                            }
                        }

                        if (((CardCapabilityContainer) dataObject).getSecurityObjectBuffer() != null)
                            s_logger.info("Security Object Buffer: {}", Hex.encodeHexString(((CardCapabilityContainer) dataObject).getSecurityObjectBuffer()));


                        s_logger.info("Error Detection Code Tag Present: {}", ((CardCapabilityContainer) dataObject).getErrorDetectionCode());

                        

                    }
                }
            }
        } catch (SQLException e) {
            s_logger.error("Failed to read configuration", e);
        }

        LauncherDiscoveryRequestBuilder suiteBuilder = LauncherDiscoveryRequestBuilder.request();
        List<DiscoverySelector> discoverySelectors = new ArrayList<>();
        ConformanceTestDatabase ctd = new ConformanceTestDatabase(conn);
        try (Statement testStatement = conn.createStatement()) {
            ResultSet rs = testStatement.executeQuery(TEST_SET);
            while(rs.next()) {
                TestCaseModel testCase = new TestCaseModel(ctd);
                testCase.retrieveForId(rs.getInt("Id"));
                int disabled = rs.getInt("Disabled");
                String groupName = rs.getString("TestGroup");
                String testNameFromConfig = rs.getString("TestCaseIdentifier");
                if(groupName == null || groupName.isEmpty()) {
                    s_logger.error("Record {} from configuration file {} contains no valid group name. This is a bug.",
                            rs.getInt("Id"), cmd.getOptionValue("config"));
                    System.exit(1);
                }
                if(disabled != 0)
                {
                    s_logger.info("Test {} was disabled in configuration", groupName);
                    continue;
                }
                Class<?> testClass = null;
                try {
                    testClass = Class.forName("gov.gsa.conformancelib.tests." + groupName);
                    for(Method m : testClass.getMethods()) {
                        s_logger.debug("method: {}", m.getName());
                    }
                } catch (ClassNotFoundException e) {
                    s_logger.error("{} was configured in the database but could not be found.", groupName);
                    break;
                }
                if(testNameFromConfig != null && !testNameFromConfig.isEmpty()) {
                    String testName = testNameFromConfig;
                    if (!testNameFromConfig.startsWith("test")) testName = "test" + testNameFromConfig;
                    discoverySelectors.add(selectMethod("gov.gsa.conformancelib.tests." + groupName + "#" + testName + "(org.junit.jupiter.api.TestReporter)"));
                    s_logger.debug("Adding {}.{} from config", groupName, testName);
                } else {
                    discoverySelectors.add(selectClass(testClass));
                    s_logger.debug("Adding all tests from {} from config", groupName);
                }
            }
        } catch (SQLException e) {
            s_logger.error("Could not read test selection from configuration");
        }
        suiteBuilder.selectors(discoverySelectors);
        LauncherDiscoveryRequest ldr = suiteBuilder.build();
        Launcher l = LauncherFactory.create();
        //TestPlan tp = l.discover(ldr);
        PrintWriter out = new PrintWriter(System.out);
        SummaryGeneratingListener summaryListener = registerListeners(out, l);
        l.registerTestExecutionListeners(summaryListener);
        l.execute(ldr);
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
