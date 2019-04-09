package gov.gsa.pivconformancegui;

import java.awt.EventQueue;

import javax.print.attribute.standard.JobMessageFromOperator;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JMenuBar;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JRadioButtonMenuItem;
import javax.swing.UIManager;

import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import gov.gsa.conformancelib.configuration.ConfigurationException;
import gov.gsa.conformancelib.configuration.ConformanceTestDatabase;
import gov.gsa.pivconformance.utils.PCSCUtils;

import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JSplitPane;

public class GuiRunnerApplication {

	private JFrame m_mainFrame;
	private DebugWindow m_debugFrame;
	//private TestTreePanel m_treePanel;
	private MainWindowContentPane m_mainContent;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					PCSCUtils.ConfigureUserProperties();
					UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
					GuiRunnerApplication window = new GuiRunnerApplication();
					GuiRunnerAppController c = GuiRunnerAppController.getInstance();
					c.setApp(window);
					LoggerContext lc = (LoggerContext) LoggerFactory.getILoggerFactory();
					GuiDebugAppender a = new GuiDebugAppender("%date %level [%thread] %logger{10} [%file:%line] %msg%n");
					a.setContext(lc);
					a.start();
					Logger logger = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
					logger.addAppender(a);
					ConformanceTestDatabase db = new ConformanceTestDatabase(null);
					String errorMessage = null;
					String dbFilename = "85b_tests.db";
					boolean opened = false;
					try {
						db.openDatabaseInFile(dbFilename);
						opened = true;
					} catch(ConfigurationException ce) {
						errorMessage = ce.getMessage();
					}
					c.setTestDatabase(db);
					window.m_mainContent.getTestExecutionPanel().refreshDatabaseInfo();
					// XXX *** find out why this isn't coming from user info
					if(opened) window.m_mainContent.getTestExecutionPanel().getDatabaseNameField().setText(dbFilename);
					window.m_mainFrame.setVisible(true);
					if(errorMessage != null) {
						JOptionPane msgBox = new JOptionPane(errorMessage, JOptionPane.ERROR_MESSAGE);
						JDialog dialog = msgBox.createDialog(window.m_mainFrame, "Error");
						dialog.setAlwaysOnTop(true);
						dialog.setVisible(true);
					}
					TestExecutionController tc = TestExecutionController.getInstance();
					tc.setTestExecutionPanel(window.m_mainContent.getTestExecutionPanel());
					tc.setTestTreePanel(window.m_mainContent.getTreePanel());
					
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public GuiRunnerApplication() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		m_mainFrame = new JFrame();
		m_mainFrame.setBounds(100, 100, 1024, 768);
		m_mainFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		m_mainFrame.setTitle("PIV Card Conformance Tool");
		
		
		JMenuBar menuBar = new JMenuBar();
		m_mainFrame.setJMenuBar(menuBar);
		
		JMenu mnFile = new JMenu("File");
		menuBar.add(mnFile);
		
		JMenuItem mntmOpen = new JMenuItem(new OpenDatabaseAction("Open Database..."));
		mnFile.add(mntmOpen);
		
		JMenuItem mntmExit = new JMenuItem("Exit");
		mntmExit.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				System.exit(0);
			}
		});
		mnFile.add(mntmExit);
		
		JMenu mnEdit = new JMenu("Edit");
		menuBar.add(mnEdit);
		
		JMenuItem mntmCut = new JMenuItem("Cut");
		mnEdit.add(mntmCut);
		
		JMenuItem mntmCopy = new JMenuItem("Copy");
		mnEdit.add(mntmCopy);
		
		JMenuItem mntmPaste = new JMenuItem("Paste");
		mnEdit.add(mntmPaste);
		
		JMenu mnView = new JMenu("View");
		menuBar.add(mnView);
		
		JRadioButtonMenuItem rdbtnmntmSimplified = new JRadioButtonMenuItem("Simplified");
		mnView.add(rdbtnmntmSimplified);
		
		JRadioButtonMenuItem rdbtnmntmAdvanced = new JRadioButtonMenuItem("Advanced");
		mnView.add(rdbtnmntmAdvanced);
		
		JMenu mnHelp = new JMenu("Help");
		menuBar.add(mnHelp);
		
		JMenuItem mntmAboutPivCard = new JMenuItem("About PIV Card Conformance Tool");
		mnHelp.add(mntmAboutPivCard);
		
		JMenuItem mntmShowDebugWindow = new JMenuItem(new ShowDebugWindowAction("Show Debugging Tools..."));
		mnHelp.add(mntmShowDebugWindow);
		
		m_mainFrame.getContentPane().add(new GuiRunnerToolbar(), BorderLayout.NORTH);
		
		m_mainContent = new MainWindowContentPane();
		m_mainFrame.getContentPane().add(m_mainContent.getSplitPane(), BorderLayout.CENTER);
		
		

		m_debugFrame = new DebugWindow("Debugging Tools");
		m_debugFrame.setBounds(150, 150, 640, 600);
	}

	public JFrame getMainFrame() {
		return m_mainFrame;
	}
	
	public DebugWindow getDebugFrame() {
		return m_debugFrame;
	}

	public void setMainFrame(JFrame mainFrame) {
		m_mainFrame = mainFrame;
	}

	public TestTreePanel getTreePanel() {
		return m_mainContent.getTreePanel();
	}
	
	public boolean isDebugPaneVisible() {
		return false;
	}
}
