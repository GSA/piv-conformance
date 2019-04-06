package gov.gsa.conformancelib.pivconformancetools;

import gov.gsa.conformancelib.configuration.CardInfoController;
import gov.gsa.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.conformancelib.configuration.ConformanceTestDatabase;
import gov.gsa.conformancelib.configuration.ParameterProviderSingleton;
import gov.gsa.conformancelib.configuration.ParameterUtils;
import gov.gsa.conformancelib.configuration.TestCaseModel;
import gov.gsa.conformancelib.configuration.TestStepModel;
import gov.gsa.conformancelib.junitoptions.Theme;
//import gov.gsa.conformancelib.tests.SignedObjectVerificationTests;
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
import java.io.Console;
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
        s_options.addOption("a", "appPin", true, "applicationPin to use for testing");
        s_options.addOption("d", "parameterDebug", false, "enable junit parameter debugging");
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
        boolean enableVerboseParameterDebugging = false;
        if(cmd.hasOption("parameterDebug")) {
        	enableVerboseParameterDebugging = true;
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
        if(cmd.hasOption("appPin")) {
        	String appPin = cmd.getOptionValue("appPin");
        	css.setApplicationPin(appPin);
        } else {
          Console cons = System.console();
          char[] passwd;
          if (cons != null && (passwd = cons.readPassword("[Enter %s]", "Application Pin")) != null) {
        	  css.setApplicationPin(new String(passwd));
          }
        }

        try (Statement configStatement = conn.createStatement()) {
            ResultSet rs = configStatement.executeQuery(FIRST_CONFIG);
            rs.next();
            String readerName = null;
            try {
            	readerName = rs.getString("ReaderName");
            } catch(SQLException e) {
            	//no need to carp now... this'll just come from css
            }
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
                }
                
                if(CardInfoController.getEncodedRetries() > 1) {
                	if(!CardInfoController.checkPin(true)) {
                		s_logger.error("Application PIN is invalid");
                		System.exit(1);
                	} else {
                		s_logger.info("Verified Application PIN");
                	}
                } else {
                	s_logger.error("PIN retry count is too low. Proceeding with tests risks locking the card");
                	System.exit(1);
                }
            }
        } catch (SQLException e) {
            s_logger.error("Failed to read configuration", e);
        }

        
        
        ConformanceTestDatabase ctd = new ConformanceTestDatabase(conn);
        PrintWriter out = new PrintWriter(System.out);
        SummaryGeneratingListener summaryListener = new SummaryGeneratingListener();
        
        
        try (Statement testStatement = conn.createStatement()) {
            ResultSet rs = testStatement.executeQuery(TEST_SET);
            while(rs.next()) {
                TestCaseModel testCase = new TestCaseModel(ctd);
                testCase.retrieveForId(rs.getInt("Id"));
                
                String groupName = rs.getString("TestGroup");
                String testNameFromConfig = rs.getString("TestCaseIdentifier");
                /*if(groupName == null || groupName.isEmpty()) {
                    s_logger.error("Record {} from configuration file {} contains no valid group name. This is a bug.",
                            rs.getInt("Id"), cmd.getOptionValue("config"));
                    System.exit(1);
                }*/
                if(!testCase.isEnabled())
                {
                    s_logger.info("Test {} was disabled in configuration", groupName);
                    continue;
                }
                LauncherDiscoveryRequestBuilder suiteBuilder = LauncherDiscoveryRequestBuilder.request();
                List<DiscoverySelector> discoverySelectors = new ArrayList<>();
                List<TestStepModel> steps = testCase.getSteps();
                for(TestStepModel currentStep : steps) {
                	Class<?> testClass = null;
                	String className = currentStep.getTestClassName();
                	String methodName = currentStep.getTestMethodName();
                	List<String> parameters = currentStep.getParameters();
                	String parameterString = null;
                	if(parameters != null) {
                		parameterString = ParameterUtils.CreateFromList(parameters);
                		if(enableVerboseParameterDebugging) s_logger.debug("processing {} as parameters for {}.{}", parameterString, className, methodName);
                	}
                	String fqmn = className;
                    try {
                        testClass = Class.forName(className);
                        for(Method m : testClass.getDeclaredMethods()) {
                        	if(enableVerboseParameterDebugging)  s_logger.debug("searching {}: {}", methodName, m.getName());
                        	if(m.getName().contentEquals(methodName)) {
                        		fqmn += "#" + m.getName() + "(";
                        		Class<?>[] methodParameters = m.getParameterTypes();
                        		int nMethodParameters = 0;
                        		for(Class<?> c : methodParameters) {
                        			if(nMethodParameters >= 1) {
                        				fqmn += ", ";
                        			}
                        			fqmn += c.getName();
                        			nMethodParameters++;
                        		}
                        		fqmn += ")";
                        		if(enableVerboseParameterDebugging) s_logger.debug("method: {}", fqmn);
                        	}
                            
                        }
                    } catch (ClassNotFoundException e) {
                        s_logger.error("{} was configured in the database but could not be found.", groupName);
                        break;
                    }
                    if(className != null && !className.isEmpty() && testClass != null) {
                        //String testName = testNameFromConfig;
                        discoverySelectors.add(selectMethod(fqmn));
                        ParameterProviderSingleton.getInstance().addNamedParameter(fqmn, parameters);
                        s_logger.debug("Adding {} from config", fqmn);
                    }
                	
                }
                suiteBuilder.selectors(discoverySelectors);
                suiteBuilder.configurationParameter("TestCaseIdentifier", testNameFromConfig);
                LauncherDiscoveryRequest ldr = suiteBuilder.build();
                
                Launcher l = LauncherFactory.create();
                List<TestExecutionListener> listeners = new ArrayList<TestExecutionListener>();
                listeners.add(summaryListener);
                registerListeners(out, l, listeners);
                //l.registerTestExecutionListeners(summaryListener);
                l.execute(ldr);
            }
        } catch (SQLException e) {
            s_logger.error("Could not read test selection from configuration");
        }
        //suiteBuilder.selectors(discoverySelectors);
        // XXX *** TODO: Need to add key/value to each suite so that logging can be fixed up
        
        //TestPlan tp = l.discover(ldr);
        

        System.out.println("--------------------------------------------------------------");
        TestExecutionSummary summary = summaryListener.getSummary();
        if(summary == null) {
        	s_logger.error("Failed to record test summary");
        }
        List<TestExecutionSummary.Failure> failures = summary.getFailures();
        for(TestExecutionSummary.Failure f : failures) {
            TestIdentifier ti = f.getTestIdentifier();
            System.out.println(String.format("Test failure: {}", ti.getDisplayName()));
        }
        summary.printTo(new PrintWriter(System.out));

    }
    private static void registerListeners(PrintWriter out, Launcher launcher, List<TestExecutionListener> listeners) {    
        for(TestExecutionListener listener : listeners) {
        	launcher.registerTestExecutionListeners(listener);
        }
        launcher.registerTestExecutionListeners(createDetailsPrintingListener(out));
    }

    private static TestExecutionListener createDetailsPrintingListener(PrintWriter out) {
        boolean disableAnsiColors = false;//options.isAnsiColorOutputDisabled();
        Theme theme = Theme.valueOf(Charset.defaultCharset());//options.getTheme();
        return new gov.gsa.conformancelib.pivconformancetools.junitconsole.VerboseTreePrintingListener(out, disableAnsiColors, 16, theme);
    }
}
