package gov.gsa.conformancelib.configuration;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import org.apache.ibatis.jdbc.ScriptRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConformanceTestDatabase {
	private static final Logger s_logger = LoggerFactory.getLogger(ConformanceTestDatabase.class);
	private static final String TEST_SET = "SELECT * from TestCases where Enabled=1";
	
	public ConformanceTestDatabase(Connection conn) {
		setConnconnection(conn);
	}
	
	public Connection getConnection() {
		return m_conn;
	}

	public void setConnconnection(Connection conn) {
		m_conn = conn;
	}
	
	public void openDatabaseInFile(String filename) throws ConfigurationException {
		Connection conn = null;
        
        File f = new File(filename);
        if (!f.exists()) {
            s_logger.error("No such file: {}", filename);
            throw new ConfigurationException("Database file " + filename + " does not exist");
        }

        String dbUrl = null;
        try {
            dbUrl = "jdbc:sqlite:" + f.getCanonicalPath();
        } catch (IOException e) {
            s_logger.error("Unable to calculate canonical name for database file", e);
            throw new ConfigurationException("Unable to calculate canonical name for database file", e);
        }
        try {
            conn = DriverManager.getConnection(dbUrl);
        } catch (SQLException e) {
            s_logger.error("Unable to establish JDBC connection for SQLite database", e);
            throw new ConfigurationException("Unable to establish JDBC connection for SQLite database", e);
        }
        if (conn != null) {
            s_logger.debug("Created sql connection for {}", filename);
            DatabaseMetaData metaData = null;
            try {
                metaData = conn.getMetaData();
                s_logger.debug("Driver: {} version {}", metaData.getDriverName(), metaData.getDriverVersion());
            } catch (SQLException e) {
                s_logger.error("Unable to read driver metadata", e);
            }
        }
        m_conn = conn;
        s_logger.info("Opened conformance test database in {}", filename);
	}
	
	public List<TestCaseModel> getTestCases() {
		ArrayList<TestCaseModel> rv = new ArrayList<TestCaseModel>();
		try (Statement testStatement = m_conn.createStatement()) {
            ResultSet rs = testStatement.executeQuery(TEST_SET);
            while(rs.next()) {
                TestCaseModel testCase = new TestCaseModel(this);
                testCase.retrieveForId(rs.getInt("Id"));
                rv.add(testCase);
            }
		} catch(SQLException e) {
			s_logger.error("Failed to retrieve test cases from database");
		}
		return rv;
	}
	
	public void populateDefault() throws ConfigurationException {
		if(m_conn == null) {
			s_logger.error("Attempting to populate conformance test database without a JDBC connection");
			throw new ConfigurationException("ConformanceTestDatabase cannot be populated without a JDBC connection.");
		}
		InputStream sqlIS = this.getClass().getResourceAsStream("/conformance-schema.sql");
		Reader r = new InputStreamReader(sqlIS);
		if(sqlIS == null) {
			s_logger.error("Unable to load conformance-schema.sql from classpath.");
			throw new ConfigurationException("ConformanceTestDatabase cannot load sql file from classpath.");
		}
		ScriptRunner sr = new ScriptRunner(m_conn);
		sr.setAutoCommit(true);
		sr.setStopOnError(true);
		try {
			sr.runScript(r);
		} catch(Exception e) {
			s_logger.error("Unable to populate database with defaults", e);
			throw new ConfigurationException("Failed to execute SQL script", e);
		}
		try {
			sqlIS.close();
		} catch (IOException e) {
			s_logger.error("Caught IOException while closing sql file", e);
			throw new ConfigurationException("Failed to close sql file", e);
		}
	}
	
	public void addTestCase(String[] testCaseDescription ) throws ConfigurationException {
		if(m_conn == null) {
			s_logger.error("Attempting to populate conformance test database without a JDBC connection");
			throw new ConfigurationException("ConformanceTestDatabase cannot be populated without a JDBC connection.");
		}
		
		try {
			m_conn.setAutoCommit(false);
			String query = " insert into TestCases (TestCaseIdentifier, TestCaseDescription) values (?, ?)";
			
			PreparedStatement preparedStmt = m_conn.prepareStatement(query);
			preparedStmt.setString (1, testCaseDescription[0]);
			preparedStmt.setString (2, testCaseDescription[1]);
			preparedStmt.execute();
			m_conn.commit();
		
		} catch (SQLException e ) {
			try {
	            System.err.print("Transaction is being rolled back");
	            m_conn.rollback();
	        } catch(SQLException excep) {
	        	throw new ConfigurationException("Failed to roll back transaction", excep);
	        }
		}
		// do some SQL stuff
	}

	private Connection m_conn;
}
