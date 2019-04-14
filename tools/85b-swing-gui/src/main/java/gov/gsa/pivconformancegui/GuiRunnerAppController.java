package gov.gsa.pivconformancegui;

import java.net.URL;

import javax.swing.ImageIcon;
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
	private RollingFileAppender<?> m_ConformanceTestCsvAppender;
	
	private OpenDatabaseAction m_openDatabaseAction;
	private ShowDebugWindowAction m_showDebugWindowAction;
	private RunAllTestsAction m_runAllTestsAction;
	private ShowOidDialogAction m_showOidDialogAction;
	private ToggleTestTreeAction m_toggleTreeAction;
	private DisplayAboutDialogAction m_displayAboutDialogAction;
	
	public void reset() {
		m_testDatabase = null;
		m_app = null;
		m_ConformanceTestCsvAppender = null;
		m_openDatabaseAction = null;
		m_showDebugWindowAction = null;
		m_runAllTestsAction = null;
		createActions();
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
	
	public RollingFileAppender<?> getConformanceTestCsvAppender() {
		return m_ConformanceTestCsvAppender;
	}

	public void setConformanceTestCsvAppender(RollingFileAppender<?> conformanceTestCsvAppender) {
		m_ConformanceTestCsvAppender = conformanceTestCsvAppender;
	}

	public JFrame getMainFrame() {
		return m_app.getMainFrame();
	}
	
	public OpenDatabaseAction getOpenDatabaseAction() {
		return m_openDatabaseAction;
	}

	public ShowDebugWindowAction getShowDebugWindowAction() {
		return m_showDebugWindowAction;
	}

	public RunAllTestsAction getRunAllTestsAction() {
		return m_runAllTestsAction;
	}
	
	public ShowOidDialogAction getShowOidDialogAction() {
		return m_showOidDialogAction;
	}

	public DisplayAboutDialogAction getDisplayAboutDialogAction() {
		return m_displayAboutDialogAction;
	}

	public ToggleTestTreeAction getToggleTestTreeAction() {
		return m_toggleTreeAction;
	}

	// this used to toggle the window, but now that we're off RCP and in a separate JFrame, the [x] can be used to hide and this just shows it
	public void showDebugWindow() {
		DebugWindow window = m_app.getDebugFrame();
		if(!window.isVisible()) {
			window.setVisible(true);
		}
	}
	
	public void showOidDialog() {
		s_logger.error("Stubbed out showOidDialog() is still here");
	}

	public void showAboutDialog() {
		s_logger.error("Stubbed out showAboutDialog() is still here");
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
	
	protected void createActions() {
		ImageIcon openIcon = getActionIcon("folder", "Open");
		m_openDatabaseAction = new OpenDatabaseAction("Open Database", openIcon, "Open a conformance test database");
	    ImageIcon runIcon = getActionIcon("building_go", "Run");
	    m_runAllTestsAction = new RunAllTestsAction("Run all tests", runIcon, "Run all available tests in database");
	    ImageIcon debugIcon = getActionIcon("application_xp_terminal", "Debug");
	    m_showDebugWindowAction = new ShowDebugWindowAction("Show Debugging tools", debugIcon, "Show detailed log and debugging tools");
	    ImageIcon oidIcon = getActionIcon("application_view_list", "Override OIDs");
	    m_showOidDialogAction = new ShowOidDialogAction("Override test OIDs...", oidIcon, "Use alternative Policy OIDs and EKU OIDs");
	    ImageIcon toggleIcon = getActionIcon("application_side_tree", "Toggle Tree");
	    m_toggleTreeAction = new ToggleTestTreeAction("Toggle test tree view", toggleIcon, "Show or hide the test tree");
	    
	}
	
	protected ImageIcon getActionIcon(String imageName, String altText) {
		String imgLocation = "/icons/" + imageName + ".png";
		URL imageUrl = GuiRunnerAppController.class.getResource(imgLocation);
		if(imageUrl == null) {
			s_logger.error("Unable to get image at classpath location {}", imgLocation);
			return null;
		}
		return new ImageIcon(imageUrl, altText);
	}
}
