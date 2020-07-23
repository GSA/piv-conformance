package gov.gsa.pivconformancegui;

import java.lang.reflect.InvocationTargetException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import javax.swing.JProgressBar;
import javax.swing.SwingUtilities;
import javax.swing.tree.DefaultTreeModel;

import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.engine.reporting.ReportEntry;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.conformancelib.configuration.TestCaseModel;
import gov.gsa.conformancelib.configuration.TestStatus;


public class GuiTestListener implements TestExecutionListener {
	
	// for log events intended to troubleshoot the listener
	private static final Logger s_logger = LoggerFactory.getLogger(GuiTestListener.class);
	private static Logger s_testProgressLogger = null;
	private static Logger s_testResultLogger = null;
	
	private String m_testCaseIdentifier;
	private String m_testCaseDescription;
	private boolean m_testCaseExpectedResult;
	private JProgressBar m_progressBar;
	
	Map<TestIdentifier, TestExecutionResult> m_testStepResults;
	boolean m_atomFailed;
	boolean m_atomAborted;

	@Override
	public void testPlanExecutionStarted(TestPlan testPlan) {
		if (s_testProgressLogger == null)
			s_testProgressLogger = LoggerFactory.getLogger("gov.gsa.conformancelib.testProgress");
		if (s_testResultLogger == null)
			s_testResultLogger = LoggerFactory.getLogger("gov.gsa.conformancelib.testResult");
		TestExecutionListener.super.testPlanExecutionStarted(testPlan);
		m_atomAborted = false;
		m_atomFailed = false;
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
		if (s_testProgressLogger == null)
			s_testProgressLogger = LoggerFactory.getLogger("gov.gsa.conformancelib.testProgress");
		if (s_testResultLogger == null)
			s_testResultLogger = LoggerFactory.getLogger("gov.gsa.conformancelib.testResult");		
		TestExecutionListener.super.testPlanExecutionFinished(testPlan);
		s_testProgressLogger.info("Test plan finished for conformance test {}", m_testCaseIdentifier);
		s_testResultLogger.info("{},\"{}\",{},{}", m_testCaseIdentifier, m_testCaseDescription,
				m_testCaseExpectedResult ? "Pass" : "Fail",
				(m_atomAborted || m_atomFailed) ? "Fail" : "Pass"); 
		GuiTestCaseTreeNode tcNode = GuiRunnerAppController.getInstance().getApp().getTreePanel().getNodeByName(m_testCaseIdentifier);
		if(tcNode != null) {
			TestCaseModel tcModel = tcNode.getTestCase();
			if(tcModel != null) {
				tcModel.setTestStatus(m_atomAborted || m_atomFailed ? TestStatus.FAIL : TestStatus.PASS);
			}
		}
		DefaultTreeModel model = GuiRunnerAppController.getInstance().getApp().getTreePanel().getTreeModel();
		try {
			SwingUtilities.invokeAndWait(() -> {
				m_progressBar.setString(m_testCaseIdentifier + " Finished.");
				m_progressBar.setValue(m_progressBar.getValue()+1);
				if(model != null && tcNode != null) model.nodeChanged(tcNode);
			});
		} catch (InterruptedException | InvocationTargetException e) {
			s_logger.error("Failed to update progress bar on secondary thread", e);
		}
	}

	@Override
	public void executionStarted(TestIdentifier testIdentifier) {
		if (s_testProgressLogger == null)
			s_testProgressLogger = LoggerFactory.getLogger("gov.gsa.conformancelib.testProgress");
		if (s_testResultLogger == null)
			s_testResultLogger = LoggerFactory.getLogger("gov.gsa.conformancelib.testResult");
		TestExecutionListener.super.executionStarted(testIdentifier);
		String displayName = testIdentifier.getDisplayName();
		//if(!testIdentifier.isTest()) return;
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
		if (s_testProgressLogger == null)
			s_testProgressLogger = LoggerFactory.getLogger("gov.gsa.conformancelib.testProgress");
		if (s_testResultLogger == null)
			s_testResultLogger = LoggerFactory.getLogger("gov.gsa.conformancelib.testResult");
		TestExecutionListener.super.executionFinished(testIdentifier, testExecutionResult);
		
		String displayName = testIdentifier.getDisplayName();
		//if(!testIdentifier.isTest()) return;
		m_testStepResults.put(testIdentifier, testExecutionResult);
		if(testExecutionResult.getStatus() == TestExecutionResult.Status.FAILED) {
			m_atomFailed = true;
			s_testProgressLogger.error("Test atom {}:{} failed", m_testCaseIdentifier, displayName);
		}
		if(testExecutionResult.getStatus() == TestExecutionResult.Status.ABORTED) {
			m_atomAborted = true;
			s_testProgressLogger.error("Test atom {}:{} aborted", m_testCaseIdentifier, displayName);
		}

		Optional<Throwable> exception = testExecutionResult.getThrowable();
		if(exception.isPresent()) s_logger.error("Caused by:", exception.get());
		if(displayName != "JUnit Jupiter") {
			s_testProgressLogger.info("Finished {}:{}", m_testCaseIdentifier, displayName);
		}
	}

	@Override
	public void reportingEntryPublished(TestIdentifier testIdentifier, ReportEntry entry) {
		if (s_testProgressLogger == null)
			s_testProgressLogger = LoggerFactory.getLogger("gov.gsa.conformancelib.testProgress");
		if (s_testResultLogger == null)
			s_testResultLogger = LoggerFactory.getLogger("gov.gsa.conformancelib.testResult");
		TestExecutionListener.super.reportingEntryPublished(testIdentifier, entry);
		s_testResultLogger.info("{}: {} {}", m_testCaseIdentifier, testIdentifier.getDisplayName(), "Placeholder" );
	}

	public GuiTestListener() {
		m_testStepResults = new LinkedHashMap<TestIdentifier, TestExecutionResult>();
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

	public String getTestCaseDescription() {
		return m_testCaseDescription;
	}

	public void setTestCaseDescription(String testCaseDescription) {
		m_testCaseDescription = testCaseDescription;
	}

	public boolean getTestCaseExpectedResult() {
		return m_testCaseExpectedResult;
	}

	public void setTestCaseExpectedResult(boolean testCaseExpectedResult) {
		m_testCaseExpectedResult = testCaseExpectedResult;
	}

}
