package gov.gsa.conformancelib.utilities;

import gov.gsa.conformancelib.configuration.ConfigurationException;
import gov.gsa.conformancelib.configuration.ConformanceTestDatabase;
import gov.gsa.pivconformance.utils.VersionUtils;
import org.apache.commons.cli.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.io.BufferedReader;
import java.lang.invoke.MethodHandles;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.SQLException;


public class SQLiteDBGenerator {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(SQLiteDBGenerator.class);
    private static final Options s_options = new Options();
    static {
        s_options.addOption("h", "help", false, "Print this help and exit");
        s_options.addOption("d", "database", true, "path to database file");
        s_options.addOption("c", "csv", true, "path to the csv file containing test cases");
    }

    private static void PrintHelpAndExit(int exitCode) {
        new HelpFormatter().printHelp("SQLiteDBGenerator <options>", s_options);
        System.exit(exitCode);
    }

    public static void main(String[] args) {
        s_logger.info("main class: {}", MethodHandles.lookup().lookupClass().getSimpleName());
        s_logger.info("package version: {}", VersionUtils.GetPackageVersionString());
        //s_logger.info("build time: {}", VersionUtils.GetPackageBuildTime());

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

        if(cmd.hasOption("database")) {
            String dbParam = cmd.getOptionValue("database");
            File f = new File(dbParam);
            if(f.exists()) {
                s_logger.error("Cowardly refusing to overwrite existing file {}", dbParam);
                System.exit(1);
            }
            String dbUrl = null;
            try {
                dbUrl = "jdbc:sqlite:" + f.getCanonicalPath();
            } catch (IOException e) {
                s_logger.error("Unable to calculate canonical name for database file", e);
                System.exit(1);
            }
            Connection conn = null;
            try {
                conn = DriverManager.getConnection(dbUrl);
            } catch (SQLException e) {
                s_logger.error("Unable to establish JDBC connection for SQLite database", e);
            }
            if(conn != null) {
                s_logger.debug("Created sql connection for {}", dbParam);
                DatabaseMetaData metaData = null;
                try {
                    metaData = conn.getMetaData();
                    s_logger.debug("Driver: {} version {}", metaData.getDriverName(), metaData.getDriverVersion());
                } catch (SQLException e) {
                    s_logger.error("Unable to read driver metadata", e);
                }
            }
            ConformanceTestDatabase cdb = new ConformanceTestDatabase(conn);
            try {
				cdb.populateDefault();
			} catch (ConfigurationException e) {
				s_logger.error("Caught configuration exception", e);
			}
            
            if(cmd.hasOption("csv")) {
                String csvParam = cmd.getOptionValue("csv");
                
                FileReader fr = null;
                
                try {
    	            fr = new FileReader(csvParam);
                } catch (FileNotFoundException e) {
    				s_logger.error("CSV file {} does not exist", csvParam);
                    System.exit(1);
    			}            
                
                BufferedReader br = null;
                String line = "";
                String cvsSplitBy = ",";
                try {

                	s_logger.debug("Starting to add test cases from {}", csvParam);
                    br = new BufferedReader(fr);
                    //read the column headers
                    line = br.readLine();
                    //Iterate over the rest
                    while ((line = br.readLine()) != null) {

                        String[] testCase = line.split(cvsSplitBy);                        
                        
                        if(testCase.length != 2) {
                        	s_logger.error("Test Case defenition must contain both \"Test Case\" and \"Test Defenition\", ", csvParam);
                        }
                        	
                        try {
                        	cdb.addTestCase(testCase);
            			} catch (ConfigurationException e) {
            				s_logger.error("Caught configuration exception", e);
            			}                        
                    }
                    
                    s_logger.debug("Finished adding test cases from {}", csvParam);

                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                } finally {
                    if (br != null) {
                        try {
                            br.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }
        }
        

    }
}
