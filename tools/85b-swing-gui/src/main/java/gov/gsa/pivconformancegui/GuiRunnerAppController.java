package gov.gsa.pivconformancegui;

import javax.swing.JFrame;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.qos.logback.core.rolling.RollingFileAppender;
import gov.gsa.conformancelib.configuration.ConformanceTestDatabase;

public class GuiRunnerAppController {
	private static final Logger s_logger = LoggerFactory.getLogger(GuiRunnerAppController.class);
	
	// more than one controller will cause problems
	private static final GuiRunnerAppController INSTANCE = new GuiRunnerAppController();
	
	private ConformanceTestDatabase m_testDatabase;
	private GuiRunnerApplication m_app;
	private RollingFileAppender m_ConformanceTestCsvAppender;
	
	public void reset() {
		m_testDatabase = null;
		m_app = null;
	}
	
	private GuiRunnerAppController() {
		reset();
	}
	
	public static GuiRunnerAppController getInstance() {
		return INSTANCE;
	}

	public ConformanceTestDatabase getTestDatabase() {
		return m_testDatabase;
	}

	public void setTestDatabase(ConformanceTestDatabase testDatabase) {
		m_testDatabase = testDatabase;
		if(m_app != null) reloadTree();
	}

	public GuiRunnerApplication getApp() {
		return m_app;
	}

	public void setApp(GuiRunnerApplication app) {
		m_app = app;
	}
	
	public RollingFileAppender getConformanceTestCsvAppender() {
		return m_ConformanceTestCsvAppender;
	}

	public void setConformanceTestCsvAppender(RollingFileAppender conformanceTestCsvAppender) {
		m_ConformanceTestCsvAppender = conformanceTestCsvAppender;
	}

	public JFrame getMainFrame() {
		return m_app.getMainFrame();
	}
	
	// this used to toggle the window, but now that we're off RCP and in a separate JFrame, the [x] can be used to hide and this just shows it
	public void showDebugWindow() {
		DebugWindow window = m_app.getDebugFrame();
		if(!window.isVisible()) {
			window.setVisible(true);
		}
	}
	
	public void reloadTree() {
		TestTreePanel tree = m_app.getTreePanel();
		tree.refresh();
	}
	
	public void rollConformanceCSV() {
		if(m_ConformanceTestCsvAppender == null) {
			s_logger.warn("rollConformanceCSV was called without any appender configured.");
		}
		m_ConformanceTestCsvAppender.rollover();
		Logger conformanceLogger = LoggerFactory.getLogger("gov.gsa.pivconformance.testResults");
		if(conformanceLogger != null) {
			conformanceLogger.info("TestId,TestDescription,ExpectedResult,ActualResult");
		}
	}
}
