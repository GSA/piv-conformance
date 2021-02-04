package gov.gsa.pivconformance.conformancelib.configuration;

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
import java.sql.SQLClientInfoException;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import org.apache.ibatis.jdbc.ScriptRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConformanceTestDatabase {
	private static final Logger s_logger = LoggerFactory.getLogger(ConformanceTestDatabase.class);
	private static final String TEST_SET = "SELECT * FROM TestCases WHERE Enabled = 1";
	
	public ConformanceTestDatabase(Connection conn) {
		setConnconnection(conn);
	}
	
	public Connection getConnection() {
		return m_conn;
	}

	public void setConnconnection(Connection conn) {
		m_conn = conn;
	}

	public int getTestCaseCount() {
		return this.testCaseCount;
	}

	public void setTestCaseCount(int count) {
		this.testCaseCount = count;
	}

	/**
	 * Opens the Sqlite database in the file and makes the connection handle available
	 * @param filename of the file to be opened
	 * @throws ConfigurationException
	 */
	
	public void openDatabaseInFile(String filename) throws ConfigurationException {
		Connection conn = null;
		File f = new File(filename);
        if (!f.exists()) {
            s_logger.error("No such file: {}", filename);
            throw new ConfigurationException("Database file " + filename + " does not exist");
        }

        String dbUrl = null;
        try {
        	Class.forName("org.sqlite.JDBC");
        	dbUrl = "jdbc:sqlite:" + f.getCanonicalPath();
        } catch (IOException | ClassNotFoundException e) {
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
        try {
			m_conn.setClientInfo("filename", filename);
		} catch (SQLClientInfoException e) {
			s_logger.error("setClientInfo failed for database connection.", e);
		}
        s_logger.info("Opened conformance test database in {}", filename);
	}
	
	public List<TestCaseModel> getTestCases() throws ConfigurationException {
		if(m_conn == null) {
			s_logger.error("getTestCases() called without any database");
			throw new ConfigurationException("getTestCases() called without any database.");
		}
		ArrayList<TestCaseModel> rv = new ArrayList<TestCaseModel>();
		int count = 0;
		try (Statement testStatement = m_conn.createStatement()) {
            ResultSet rs = testStatement.executeQuery(TEST_SET);
            while(rs.next()) {
                TestCaseModel testCase = new TestCaseModel(this);
                testCase.retrieveForId(rs.getInt("Id"));
                if (!testCase.getTestStatus().equals(TestStatus.TESTCATEGORY)) {
                	// If it's not a test category, then its a test we have to run
					count++;
				}
                rv.add(testCase);
            }
            //m_conn.close();
		} catch(SQLException e) {
			s_logger.error("Failed to retrieve test cases from database: {}", e.getMessage());
		}
		setTestCaseCount(count);
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
	
	/*
	 * SELECT
	 *   TestStepParameters.Id,
	 *   TestStepParameters.Value
	 * FROM
	 *   TestStepParameters
	 * JOIN
	 *   TestSteps
	 * ON
	 *   TestStepParameters.TestStepId = TestSteps.Id
	 * WHERE
	 *   TestStepParameters.value LIKE 'X509_CERTIFICATE_FOR_PIV_AUTHENTICATION:%{}%'
	 */
		
	public void addTestCase(String[] testCaseDescription ) throws ConfigurationException {
		if(m_conn == null) {
			String msg = "Conformance test database cannot be populated without a JDBC connection";
			s_logger.error(msg);
			throw new ConfigurationException(msg);
		}
		
		try {
			m_conn.setAutoCommit(false);
			String query = "INSERT INTO TestCases (TestCaseIdentifier, TestCaseDescription) values (?, ?)";
			
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
	private int testCaseCount;
}
