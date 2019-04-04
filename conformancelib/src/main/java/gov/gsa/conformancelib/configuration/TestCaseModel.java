package gov.gsa.conformancelib.configuration;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
		String query = "select TestCases.Id, TestCases.TestCaseIdentifier, TestCases.TestCaseDescription, TestCases.Status, TestCases.ExpectedStatus, " +
				"TestCases.TestGroup, TestCases.Enabled " +
				"from TestCases where TestCases.Id = ?";
										
		String stepsQuery = "select Id, TestStepId from TestsToSteps where TestsToSteps.TestId = ? order by ExecutionOrder";
		try {
			Connection conn = m_db.getConnection();
			PreparedStatement pquery = conn.prepareStatement(query);
			pquery.setInt(1, testId);
			
			ResultSet rs = pquery.executeQuery();
			rs.absolute(1);
			this.setExpectedStatus(rs.getInt("TestCases.Status"));
			this.setDescription(rs.getString("TestCases.TestDescription"));
			this.setIdentifier(rs.getString("TestCases.TestCaseIdentifier"));
			this.setStatus(rs.getInt("TestCases.Status"));
			this.setEnabled(1 == rs.getInt("TestCases.Enabled"));
			this.setTestGroupName(rs.getString("TestCases.TestGroup"));
			
			s_logger.debug("Test case {} {} instantiated from database", this.getIdentifier(), this.getDescription());
			PreparedStatement pstepsQuery = conn.prepareStatement(stepsQuery);
			pstepsQuery.setInt(1, testId);
			ResultSet prs = pstepsQuery.executeQuery();
			while(prs.next()) {
				TestStepModel ts = new TestStepModel(this.getDb());
				ts.retrieveForId(prs.getInt("TestStepId"), testId);
				m_steps.add(ts);
			}
		} catch(Exception e) {
			// XXX *** TODO: more granular exception handling		
			s_logger.error("Database error procesing test case id " + testId + ": caught unexpected exception", e);
			// rethrow here
		}
		
	}
}
