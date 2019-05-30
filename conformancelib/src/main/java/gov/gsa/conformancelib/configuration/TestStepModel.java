package gov.gsa.conformancelib.configuration;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestStepModel {
	private static Logger s_logger = LoggerFactory.getLogger(TestStepModel.class);
	
	
	public TestStepModel(ConformanceTestDatabase db) {
		m_db = db;
		m_status = -1;
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
	
	public TestStatus getTestStatus() {
		Optional<TestStatus> result = TestStatus.valueOf(m_status);
		if(!result.isPresent()) return TestStatus.NONE;
		return result.get();
	}
	
	public void setTestStatus(TestStatus s) {
		m_status = s.getValue();
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
		String query = "select TestSteps.Id as TestStepId, Description, Class, "+
				"Method, NumParameters, Status "+
				"from TestSteps left outer join TestsToSteps on TestSteps.Id = TestsToSteps.TestStepId "+
				"where TestSteps.Id = ? and TestsToSteps.TestId = ?";
								
		String parametersQuery = "select Id, TestStepId, TestId, Value from TestStepParameters " + 
                                            "where TestStepParameters.TestStepId = ? " +
                                            "order by TestStepParameters.ParamOrder";
		try {
			Connection conn = m_db.getConnection();
			PreparedStatement pquery = conn.prepareStatement(query);
			pquery.setInt(1, testStepId);
			pquery.setInt(2, testId);
			ResultSet rs = pquery.executeQuery();
			if(!rs.next()) {
				s_logger.error("Database not configured properly: no test case for id {}, step id {}", testId, testStepId);
				throw new ConfigurationException("Unable to retrieve record for test step id " + testStepId);
			}
			this.setTestClassName(rs.getString("Class"));
			this.setTestMethodName(rs.getString("Method"));
			this.setTestDescription(rs.getString("Description"));
			if(rs.getObject("Status") != null) {
				this.setStatus(rs.getInt("Status"));
			} else {
				this.setStatus(-1);
			}
			//int nParameters = rs.getInt("NumParameters");
			//s_logger.debug("Test step {} has {} parameters", this.getTestDescription(), nParameters);
			PreparedStatement pparametersQuery = conn.prepareStatement(parametersQuery);
			pparametersQuery.setInt(1, testStepId);
			//pparametersQuery.setInt(2, testId);

			ResultSet prs = pparametersQuery.executeQuery();
			int nParameters = 0;
			while(prs.next()) {
				if(m_parameters == null) m_parameters = new ArrayList<String>();
				m_parameters.add(prs.getString("Value"));
				nParameters++;
			}
			s_logger.debug("Test step {} has {} parameters", this.getTestDescription(), nParameters);
		} catch(Exception e) {
			// XXX *** TODO: more granular exception handling
			s_logger.error("Database error procesing test step id " + testStepId + ": caught unexpected exception", e);
		}
		
	}
		
}
