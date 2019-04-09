package gov.gsa.pivconformancegui;

import java.lang.reflect.InvocationTargetException;

import javax.swing.JProgressBar;
import javax.swing.SwingUtilities;

import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.engine.reporting.ReportEntry;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class GuiTestListener implements TestExecutionListener {
	
	// for log events intended to troubleshoot the listener
	private static final Logger s_logger = LoggerFactory.getLogger(GuiTestListener.class);
	private static final Logger s_testProgressLogger = LoggerFactory.getLogger("gov.gsa.pivconformance.testProgress");
	private static final Logger s_testResultLogger = LoggerFactory.getLogger("gov.gsa.pivconformance.testResults");
	
	private String m_testCaseIdentifier;
	private JProgressBar m_progressBar;

	@Override
	public void testPlanExecutionStarted(TestPlan testPlan) {
		TestExecutionListener.super.testPlanExecutionStarted(testPlan);
		s_testProgressLogger.info("Test plan started for conformance test {}", m_testCaseIdentifier);
		try {
			SwingUtilities.invokeAndWait(() -> {
				m_progressBar.setString(m_testCaseIdentifier);
			});
		} catch (InterruptedException | InvocationTargetException e) {
			s_logger.error("Failed to update progress bar on secondary thread", e);
		}
	}

	@Override
	public void testPlanExecutionFinished(TestPlan testPlan) {
		TestExecutionListener.super.testPlanExecutionFinished(testPlan);
		s_testProgressLogger.info("Test plan finished for conformance test {}", m_testCaseIdentifier);
		try {
			SwingUtilities.invokeAndWait(() -> {
				m_progressBar.setString(m_testCaseIdentifier + " Finished.");
				m_progressBar.setValue(m_progressBar.getValue()+1);
			});
		} catch (InterruptedException | InvocationTargetException e) {
			s_logger.error("Failed to update progress bar on secondary thread", e);
		}
	}

	@Override
	public void executionStarted(TestIdentifier testIdentifier) {
		TestExecutionListener.super.executionStarted(testIdentifier);
		String displayName = testIdentifier.getDisplayName();
		if(displayName != "JUnit Jupiter") {
			s_testProgressLogger.info("Started {}:{}", m_testCaseIdentifier, displayName);
			try {
				SwingUtilities.invokeAndWait(() -> {
					m_progressBar.setString(m_testCaseIdentifier + " (" + displayName + ")");
				});
			} catch (InterruptedException | InvocationTargetException e) {
				s_logger.error("Failed to update progress bar on secondary thread", e);
			}
		}
	}

	@Override
	public void executionFinished(TestIdentifier testIdentifier, TestExecutionResult testExecutionResult) {
		TestExecutionListener.super.executionFinished(testIdentifier, testExecutionResult);
		
		String displayName = testIdentifier.getDisplayName();
		if(displayName != "JUnit Jupiter") {
			s_testProgressLogger.info("Finished {}:{}", m_testCaseIdentifier, displayName);
		}
	}

	@Override
	public void reportingEntryPublished(TestIdentifier testIdentifier, ReportEntry entry) {
		TestExecutionListener.super.reportingEntryPublished(testIdentifier, entry);
		s_testResultLogger.info("{}: {} {}", m_testCaseIdentifier, testIdentifier.getDisplayName(), "Placeholder" );
	}

	public GuiTestListener() {
	}

	public String getTestCaseIdentifier() {
		return m_testCaseIdentifier;
	}

	public void setTestCaseIdentifier(String testCaseIdentifier) {
		m_testCaseIdentifier = testCaseIdentifier;
	}

	public JProgressBar getProgressBar() {
		return m_progressBar;
	}

	public void setProgressBar(JProgressBar progressBar) {
		m_progressBar = progressBar;
	}

}
