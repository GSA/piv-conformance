package gov.gsa.pivconformancegui;

import javax.swing.JFrame;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.conformancelib.configuration.ConformanceTestDatabase;

public class GuiRunnerAppController {
	private static final Logger s_logger = LoggerFactory.getLogger(GuiRunnerAppController.class);
	
	// more than one controller will cause problems
	private static final GuiRunnerAppController INSTANCE = new GuiRunnerAppController();
	
	private ConformanceTestDatabase m_testDatabase;
	private GuiRunnerApplication m_app;
	
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
	}

	public GuiRunnerApplication getApp() {
		return m_app;
	}

	public void setApp(GuiRunnerApplication app) {
		m_app = app;
	}
	
	public JFrame getMainFrame() {
		return m_app.getMainFrame();
	}
	
	// show the debug window if it's hidden, hide it if it's shown, return whether it is now visible
	public boolean toggleDebugWindow() {
		// stub for now while fixing the debug window
		return true;
	}
}
