package gov.gsa.conformancelib.configuration;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sqlite.SQLiteException;

public class TestCaseModel {
	private static Logger s_logger = LoggerFactory.getLogger(TestCaseModel.class);
	
	private List<TestStepModel> m_steps;
	private ConformanceTestDatabase m_db;
	private int m_id;
	private String m_identifier;
	private String m_description;
	private int m_status;
	private int m_expectedStatus;
    private String m_testGroupName;
    private boolean m_bEnabled;
    private String m_container;
	
	public TestCaseModel(ConformanceTestDatabase db) {
		setDb(db);
	}


	public List<TestStepModel> getSteps() {
		return m_steps;
	}



	public void setSteps(List<TestStepModel> steps) {
		m_steps = steps;
	}



	public ConformanceTestDatabase getDb() {
		return m_db;
	}



	public void setDb(ConformanceTestDatabase db) {
		m_db = db;
	}


	public int getId() {
		return m_id;
	}


	public void setId(int id) {
		m_id = id;
	}


	public String getIdentifier() {
		return m_identifier;
	}


	public void setIdentifier(String identifier) {
		m_identifier = identifier;
	}


	public String getContainer() {
		return m_container;
	}


	public void setContainer(String container) {
		m_container = container;
	}


	public String getDescription() {
		return m_description;
	}


	public void setDescription(String description) {
		m_description = description;
	}


	public int getStatus() {
		return m_status;
	}


	public void setStatus(int status) {
		m_status = status;
	}
	
	public TestStatus getTestStatus() {
		Optional<TestStatus> result = TestStatus.valueOf(m_status);
		if(!result.isPresent()) return TestStatus.NONE;
		return result.get();
	}
	
	public void setTestStatus(TestStatus s) {
		m_status = s.getValue();
	}

	public int getExpectedStatus() {
		return m_expectedStatus;
	}


	public void setExpectedStatus(int expectedStatus) {
		m_expectedStatus = expectedStatus;
	}

	public String getTestGroupName() {
		return m_testGroupName;
	}


	public boolean isEnabled() {
		return m_bEnabled;
	}


	public void setEnabled(boolean bEnabled) {
		m_bEnabled = bEnabled;
	}


	public void setTestGroupName(String name) {
		m_testGroupName = name;
	}
	
	public void retrieveForId(int testId) {
		this.setId(testId);
		String query = "select Id, TestCaseIdentifier, TestCaseDescription, Status, ExpectedStatus, " +
				"TestGroup, Enabled " +
				"from TestCases where TestCases.Id = ?";
		String containerQuery = "select TestCaseContainer from TestCases where TestCases.Id = ?";
										
		String stepsQuery = "select Id, TestStepId from TestsToSteps where TestsToSteps.TestId = ? order by ExecutionOrder";
		try {
			Connection conn = m_db.getConnection();
			PreparedStatement pquery = conn.prepareStatement(query);
			pquery.setInt(1, testId);
			
			ResultSet rs = pquery.executeQuery();
			if(!rs.next()) {
				s_logger.error("Database not configured properly: no test case for id {}", testId);
				throw new ConfigurationException("Unable to retrieve record for test case id " + testId);
			}
			this.setExpectedStatus(rs.getInt("ExpectedStatus"));
			this.setDescription(rs.getString("TestCaseDescription"));
			this.setIdentifier(rs.getString("TestCaseIdentifier"));
			if(rs.getObject("Status") != null) {
				this.setStatus(rs.getInt("Status"));
			} else {
				this.setStatus(-1);
			}
			this.setEnabled(1 == rs.getInt("Enabled"));
			this.setTestGroupName(rs.getString("TestGroup"));
			
			s_logger.debug("Test case {} {} instantiated from database", this.getIdentifier(), this.getDescription());
			PreparedStatement pstepsQuery = conn.prepareStatement(stepsQuery);
			pstepsQuery.setInt(1, testId);
			ResultSet prs = pstepsQuery.executeQuery();
			m_steps = new ArrayList<TestStepModel>();
			while(prs.next()) {
				TestStepModel ts = new TestStepModel(this.getDb());
				ts.retrieveForId(prs.getInt("TestStepId"), testId);
				m_steps.add(ts);
			}
			try {
				PreparedStatement pContainerQuery = conn.prepareStatement(containerQuery);
				pContainerQuery.setInt(1, testId);
				ResultSet crs = pContainerQuery.executeQuery();
				if(!crs.next()) {
					s_logger.warn("Test case database does not return anything for container. This is an old format database and should be updated.");
					this.setContainer(null);
				}
				this.setContainer(crs.getString("TestCaseContainer"));
			} catch(SQLiteException e) {
				this.setContainer(null);
				s_logger.warn("Test case database does not contain test case container column. This is an old format database and must be regenerated.",
						e);
			}
		} catch(Exception e) {
			// XXX *** TODO: more granular exception handling		
			s_logger.error("Database error procesing test case id " + testId + ": caught unexpected exception", e);
			// rethrow here
		}
		
	}
}
