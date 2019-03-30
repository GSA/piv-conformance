package gov.gsa.conformancelib.configuration;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestStepModel {
	private static Logger s_logger = LoggerFactory.getLogger(TestStepModel.class);
	
	
	public TestStepModel(ConformanceTestDatabase db) {
		m_db = db;
	}
	
	public ConformanceTestDatabase getDb() {
		return m_db;
	}

	public void setDb(ConformanceTestDatabase db) {
		m_db = db;
	}
	
	public List<String> getParameters() {
		return m_parameters;
	}

	public void setParameters(List<String> parameters) {
		m_parameters = parameters;
	}

	public String getTestClassName() {
		return m_testClassName;
	}

	public void setTestClassName(String testClassName) {
		m_testClassName = testClassName;
	}

	public String getTestMethodName() {
		return m_testMethodName;
	}

	public void setTestMethodName(String testMethodName) {
		m_testMethodName = testMethodName;
	}

	public String getTestDescription() {
		return m_testDescription;
	}

	public void setTestDescription(String testDescription) {
		m_testDescription = testDescription;
	}

	public int getStatus() {
		return m_status;
	}

	public void setStatus(int status) {
		m_status = status;
	}

	private ConformanceTestDatabase m_db;
	String m_testDescription;
	String m_testClassName;
	String m_testMethodName;
	List<String> m_parameters;
	int m_id;
	int m_status;
	public int getId() {
		return m_id;
	}

	public void setId(int id) {
		m_id = id;
	}
	
	public void retrieveForId(int testStepId, int testId) {
		this.setId(testStepId);
		String query = "select TestSteps.Id, TestSteps.Description, TestSteps.Class, "+
				"TestSteps.Method, TestSteps.JUnitName, TestSteps.JUnitGroup, TestSteps.NumParameters, TestsToSteps.Status "+
				"from TestSteps left outer join TestsToSteps on TestSteps.Id = TestsToSteps.TestStepId "+
				"where TestSteps.Id = ? and TestSteps.TestId = ?";
								
		String parametersQuery = "select Id, TestStepId, TestId, Value from TestStepParameters " + 
                                            "where TestStepParameters.TestStepId = ? and TestStepParameters.TestId = ? " +
                                            "order by TestStepParameters.ParamOrder";
		try {
			Connection conn = m_db.getConnection();
			PreparedStatement pquery = conn.prepareStatement(query);
			pquery.setInt(1, testStepId);
			pquery.setInt(2, testId);
			ResultSet rs = pquery.executeQuery();
			rs.absolute(1);
			this.setTestClassName(rs.getString("TestSteps.Class"));
			this.setTestMethodName(rs.getString("TestSteps.Method"));
			this.setTestDescription(rs.getString("TestSteps.Description"));
			this.setStatus(rs.getInt("TestSteps.Status"));
			int nParameters = rs.getInt("TestSteps.NumParameters");
			s_logger.debug("Test step {} has {} parameters", this.getTestDescription(), nParameters);
			PreparedStatement pparametersQuery = conn.prepareStatement(parametersQuery);
			pparametersQuery.setInt(1, testStepId);
			pparametersQuery.setInt(2, testId);
			ResultSet prs = pparametersQuery.executeQuery();
			while(prs.next()) {
				m_parameters.add(prs.getString("Value"));
			}
		} catch(Exception e) {
			// XXX *** TODO: more granular exception handling
			s_logger.error("Database error procesing test step id " + testStepId + ": caught unexpected exception", e);
		}
		
	}
		
}
