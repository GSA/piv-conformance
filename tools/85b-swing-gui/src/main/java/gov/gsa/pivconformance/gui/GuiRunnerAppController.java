package gov.gsa.pivconformance.gui;

import java.awt.Font;
import java.awt.Window;
import java.net.URL;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.UIManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.FormSpecs;
import com.jgoodies.forms.layout.RowSpec;

import gov.gsa.pivconformance.conformancelib.configuration.ConfigurationException;
import gov.gsa.pivconformance.conformancelib.configuration.ConformanceTestDatabase;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class GuiRunnerAppController {
	private static final Logger s_logger = LoggerFactory.getLogger(GuiRunnerAppController.class);
	
	// more than one controller will cause problems
	private static final GuiRunnerAppController INSTANCE = new GuiRunnerAppController();
	
	private ConformanceTestDatabase m_testDatabase;
	private GuiRunnerApplication m_app;
	private OpenDatabaseAction m_openDatabaseAction;
	private GuiRunAllTestsAction m_runAllTestsAction;
	private GuiToggleTestTreeAction m_toggleTreeAction;
	private GuiDisplayAboutDialogAction m_displayAboutDialogAction;
	private GuiDisplayTestReportAction m_displayTestReportAction;
	private OpenDefaultPIVDatabaseAction m_openDefaultPIVDatabaseAction;
	private OpenDefaultPIVIDatabaseAction m_openDefaultPIVIDatabaseAction;
	private GuiTestExecutionController m_tec;
	private String m_cctVersion;

	private JTextField pivAuthOverrideTextField;
	private JTextField digitalSignatureOverrideTextField;
	private JTextField keyManagementOverrideTextField;
	private JTextField cardAuthenticationOverrideTextField;
	private JTextField contentSigningOverrideTextField;
	public void reset() {
		m_testDatabase = null;
		m_app = null;
		m_openDatabaseAction = null;
		m_runAllTestsAction = null;
		m_toggleTreeAction = null;
		m_displayAboutDialogAction = null;
		m_displayTestReportAction = null;
		m_openDefaultPIVDatabaseAction = null;
		m_openDefaultPIVIDatabaseAction = null;
		m_tec = null;
		m_cctVersion = null;
		
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
		
		if(m_app != null && testDatabase != null)
			reloadTree();
	}

	public GuiRunnerApplication getApp() {
		return m_app;
	}

	public void setApp(GuiRunnerApplication app) {
		m_app = app;
	}

	void setTestRunLogController (GuiTestExecutionController trlc) {
		m_tec = trlc;
	}

	public GuiTestExecutionController getTestExecutionController() {
		return m_tec;
	}
	
	void setCctVersion (String cctVersion) {
		m_cctVersion = cctVersion;
	}

	public String getCctVersion() {
		return m_cctVersion;
	}
	
	public JFrame getMainFrame() {
		return m_app.getMainFrame();
	}
	
	public OpenDatabaseAction getOpenDatabaseAction() {
		return m_openDatabaseAction;
	}

	public OpenDefaultPIVDatabaseAction getOpenDefaultPIVDatabaseAction() {
		return m_openDefaultPIVDatabaseAction;
	}

	public OpenDefaultPIVIDatabaseAction getOpenDefaultPIVIDatabaseAction() {
		return m_openDefaultPIVIDatabaseAction;
	}

	public GuiRunAllTestsAction getRunAllTestsAction() {
		return m_runAllTestsAction;
	}

	public GuiDisplayAboutDialogAction getDisplayAboutDialogAction() {
		return m_displayAboutDialogAction;
	}

	public GuiToggleTestTreeAction getToggleTestTreeAction() {
		return m_toggleTreeAction;
	}

	public GuiDisplayTestReportAction getDisplayTestReportAction() {
		return m_displayTestReportAction;
	}

	public void showAboutDialog() {
		s_logger.error("Stubbed out showAboutDialog() is still here");
	}
	
	public void reloadTree() {
		GuiTestTreePanel tree = m_app.getTreePanel();
		tree.refresh();
	}

	protected void createActions() {
		ImageIcon openIcon = getActionIcon("folder", "Open");
		m_openDatabaseAction = new OpenDatabaseAction("Open Database", openIcon, "Open a conformance test database");
	    ImageIcon runIcon = getActionIcon("building_go", "Run");
	    m_runAllTestsAction = new GuiRunAllTestsAction("Run all tests", runIcon, "Run all available tests in database");
	    ImageIcon toggleIcon = getActionIcon("application_side_tree", "Toggle Tree");
	    m_toggleTreeAction = new GuiToggleTestTreeAction("Toggle test tree view", toggleIcon, "Show or hide the test tree");
	    ImageIcon displayReportIcon = getActionIcon("html", "Display HTML report");
	    m_displayTestReportAction = new GuiDisplayTestReportAction("Display Test Report", displayReportIcon, "Display test report for current log");
	    ImageIcon savingIcon = getActionIcon("folder", "Saving");
	    ImageIcon pivIcon = getActionIcon("PIV", "Open");
	    m_openDefaultPIVDatabaseAction = new OpenDefaultPIVDatabaseAction("Open Default PIV Database", pivIcon, "Open Default PIV conformance test database");
	
	    ImageIcon pivIIcon = getActionIcon("PIVI", "Open");
	    m_openDefaultPIVIDatabaseAction = new OpenDefaultPIVIDatabaseAction("Open Default PIV-I Database", pivIIcon, "Open Default PIV-I conformance test database");
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
