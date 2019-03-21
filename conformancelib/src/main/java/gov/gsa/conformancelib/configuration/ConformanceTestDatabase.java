package gov.gsa.conformancelib.configuration;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

import org.apache.ibatis.jdbc.ScriptRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConformanceTestDatabase {
	private static final Logger s_logger = LoggerFactory.getLogger(ConformanceTestDatabase.class);
	public ConformanceTestDatabase(Connection conn) {
		setConnconnection(conn);
	}
	
	public Connection getConnection() {
		return m_conn;
	}

	public void setConnconnection(Connection conn) {
		m_conn = conn;
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
