package gov.gsa.pivconformance.conformancelib.junitoptions;

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
	private static Logger s_testProgressLogger = null;
	private static Logger s_testResultLogger = null;
	
	private String m_testCaseIdentifier;

	@Override
	public void testPlanExecutionStarted(TestPlan testPlan) {
		if (s_testProgressLogger == null)
			s_testProgressLogger = LoggerFactory.getLogger("gov.gsa.conformancelib.testProgress");
		TestExecutionListener.super.testPlanExecutionStarted(testPlan);
		s_testProgressLogger.info("Test plan started for conformance test {}", m_testCaseIdentifier);
	}

	@Override
	public void testPlanExecutionFinished(TestPlan testPlan) {
		if (s_testProgressLogger == null)
			s_testProgressLogger = LoggerFactory.getLogger("gov.gsa.conformancelib.testProgress");
		TestExecutionListener.super.testPlanExecutionFinished(testPlan);
		s_testProgressLogger.info("Test plan finished for conformance test {}", m_testCaseIdentifier);
	}

	@Override
	public void executionStarted(TestIdentifier testIdentifier) {
		if (s_testProgressLogger == null)
			s_testProgressLogger = LoggerFactory.getLogger("gov.gsa.conformancelib.testProgress");
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
		if (s_testProgressLogger == null)
			s_testProgressLogger = LoggerFactory.getLogger("gov.gsa.conformancelib.testProgress");
		TestExecutionListener.super.executionFinished(testIdentifier, testExecutionResult);
		String displayName = testIdentifier.getDisplayName();
		if(displayName != "JUnit Jupiter") {
			s_testProgressLogger.info("Finished {}:{}", m_testCaseIdentifier, testIdentifier.getDisplayName());
		} else {
			s_logger.debug("{}: Skipping progress logging for 'JUnit Jupiter' because that's not really a conformance test", m_testCaseIdentifier);
		}
	}

	@Override
	public void reportingEntryPublished(TestIdentifier testIdentifier, ReportEntry entry) {
		if (s_testResultLogger == null)
			s_testResultLogger = LoggerFactory.getLogger("gov.gsa.conformancelib.testResult");
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
