package gov.gsa.conformancelib.junitoptions;

import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.engine.reporting.ReportEntry;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class ConformanceTestExecutionListener implements TestExecutionListener {
	
	// for log events intended to troubleshoot the listener
	private static final Logger s_logger = LoggerFactory.getLogger(ConformanceTestExecutionListener.class);
	private static final Logger s_testProgressLogger = LoggerFactory.getLogger("gov.gsa.pivconformance.testProgress");
	private static final Logger s_testResultLogger = LoggerFactory.getLogger("gov.gsa.pivconformance.testResults");
	
	private String m_testCaseIdentifier;

	@Override
	public void testPlanExecutionStarted(TestPlan testPlan) {
		TestExecutionListener.super.testPlanExecutionStarted(testPlan);
		s_testProgressLogger.info("Test plan started for conformance test {}", m_testCaseIdentifier);
	}

	@Override
	public void testPlanExecutionFinished(TestPlan testPlan) {
		TestExecutionListener.super.testPlanExecutionFinished(testPlan);
		s_testProgressLogger.info("Test plan finished for conformance test {}", m_testCaseIdentifier);
	}

	@Override
	public void executionStarted(TestIdentifier testIdentifier) {
		TestExecutionListener.super.executionStarted(testIdentifier);
		String displayName = testIdentifier.getDisplayName();
		if(displayName != "JUnit Jupiter") {
			s_testProgressLogger.info("Started {}: {}", m_testCaseIdentifier, displayName);
		} else {
			s_logger.debug("{}: Skipping progress logging for 'JUnit Jupiter' because that's not really a conformance test", m_testCaseIdentifier);
		}
	}

	@Override
	public void executionFinished(TestIdentifier testIdentifier, TestExecutionResult testExecutionResult) {
		TestExecutionListener.super.executionFinished(testIdentifier, testExecutionResult);
		s_testProgressLogger.info("Finished {}:{}", m_testCaseIdentifier, testIdentifier.getDisplayName());
	}

	@Override
	public void reportingEntryPublished(TestIdentifier testIdentifier, ReportEntry entry) {
		TestExecutionListener.super.reportingEntryPublished(testIdentifier, entry);
		s_testResultLogger.info("{}: {} {}", m_testCaseIdentifier, testIdentifier.getDisplayName(), "Placeholder" );
	}

	public ConformanceTestExecutionListener() {
	}

	public String getTestCaseIdentifier() {
		return m_testCaseIdentifier;
	}

	public void setTestCaseIdentifier(String testCaseIdentifier) {
		m_testCaseIdentifier = testCaseIdentifier;
	}

}
