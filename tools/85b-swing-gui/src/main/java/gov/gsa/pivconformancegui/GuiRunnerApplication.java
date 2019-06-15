package gov.gsa.pivconformancegui;

import java.awt.BorderLayout;
import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;

import javax.swing.ImageIcon;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.UIManager;
import javax.swing.text.DefaultEditorKit;

import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.core.Appender;
import ch.qos.logback.core.joran.spi.JoranException;
import ch.qos.logback.core.rolling.RollingFileAppender;
import ch.qos.logback.core.util.StatusPrinter;
import gov.gsa.conformancelib.configuration.ConfigurationException;
import gov.gsa.conformancelib.configuration.ConformanceTestDatabase;
import gov.gsa.pivconformance.utils.PCSCUtils;

public class GuiRunnerApplication {

	private static final org.slf4j.Logger s_logger = LoggerFactory.getLogger(GuiRunnerApplication.class);

	private JFrame m_mainFrame;
	private DebugWindow m_debugFrame;
	//private TestTreePanel m_treePanel;
	private MainWindowContentPane m_mainContent;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		LoggerContext ctx = (LoggerContext) LoggerFactory.getILoggerFactory();
		RollingFileAppender<?> csvAppender = null;
		try {
			System.out.println("Working Directory = " +
		              System.getProperty("user.dir"));
			File logConfigFile = new File("user_log_config.xml");
			if(logConfigFile.exists() && logConfigFile.canRead()) {
				JoranConfigurator configurator = new JoranConfigurator();
				ctx.reset();
				configurator.setContext(ctx);
				configurator.doConfigure(logConfigFile.getCanonicalPath());
			}
		} catch(JoranException e) {
			// handled by status printer
		} catch (IOException e) {
			System.err.println("Unable to resolve logging config to a readable file");
			e.printStackTrace();
		}
		StatusPrinter.printIfErrorsOccured(ctx);
		Appender<?> a = null;
		Logger testResultsLogger = (Logger) LoggerFactory.getLogger("gov.gsa.pivconformance.testResults");
		if(testResultsLogger == null) {
			s_logger.warn("No logger was configured for test results CSV");
		} else {
			a = testResultsLogger.getAppender("CONFORMANCELOG");
			if(a == null) s_logger.warn("CONFORMANCELOG appender was not configured. No CSV will be produced.");
			csvAppender = (RollingFileAppender<?>) a;
		}
		final RollingFileAppender<?> foundAppender = csvAppender;
		RollingFileAppender<?> apduAppender = null;
		Logger apduLogger = (Logger) LoggerFactory.getLogger("gov.gsa.pivconformance.apdu");
		if(apduLogger == null) {
			s_logger.info("No APDU logger is available");
		} else {
			apduAppender = (RollingFileAppender<?>) apduLogger.getAppender("APDULOG");
			if(apduAppender == null) {
				s_logger.info("No APDU log appender was configured. Disabling APDU logs.");
				apduLogger.setLevel(Level.OFF);
			}
			apduAppender.rollover();
		}
		System.setProperty("sun.security.smartcardio.t0GetResponse", "false");
		System.setProperty("sun.security.smartcardio.t1GetResponse", "false");
		//Security.insertProviderAt(new jnasmartcardio.Smartcardio(), 1);

		//Security.insertProviderAt(new de.intarsys.security.smartcard.smartcardio.SmartcardioProvider(), 1);
		
		
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
					c.setConformanceTestCsvAppender(foundAppender);
					window.m_mainContent.getTestExecutionPanel().refreshDatabaseInfo();
					// XXX *** find out why this isn't coming from user info
					window.m_mainFrame.setVisible(true);
					if(opened) {
						window.m_mainContent.getTestExecutionPanel().getDatabaseNameField().setText(dbFilename);
					} else {
						//OpenDatabaseAction dbAction = new OpenDatabaseAction("startup database");
						//dbAction.actionPerformed(new ActionEvent(window, ActionEvent.ACTION_PERFORMED, "open startup database"));
					}
					/*if(errorMessage != null) {
						JOptionPane msgBox = new JOptionPane(errorMessage, JOptionPane.ERROR_MESSAGE);
						JDialog dialog = msgBox.createDialog(window.m_mainFrame, "Error");
						dialog.setAlwaysOnTop(true);
						dialog.setVisible(true);
					}*/
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
		
		GuiRunnerAppController c = GuiRunnerAppController.getInstance();
		
		JMenuItem mntmOpen = new JMenuItem(c.getOpenDatabaseAction());
		mntmOpen.setIcon(null);
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
		
		JMenuItem mntmCut = new JMenuItem(new DefaultEditorKit.CutAction());
		mntmCut.setText("Cut");
		mnEdit.add(mntmCut);
		
		JMenuItem mntmCopy = new JMenuItem(new DefaultEditorKit.CopyAction());
		mntmCopy.setText("Copy");
		mnEdit.add(mntmCopy);
		
		JMenuItem mntmPaste = new JMenuItem(new DefaultEditorKit.PasteAction());
		mntmPaste.setText("Paste");
		mnEdit.add(mntmPaste);
		
		mnEdit.addSeparator();
		
		JMenuItem mntmChangeOids = new JMenuItem(c.getShowOidDialogAction());
		mnEdit.add(mntmChangeOids);
		
		JMenu mnView = new JMenu("View");
		menuBar.add(mnView);
		
		JMenuItem mntmToggleTestTree = new JMenuItem(c.getToggleTestTreeAction());
		mnView.add(mntmToggleTestTree);

		JMenuItem mntmDisplayTestReport = new JMenuItem(c.getDisplayTestReportAction());
		mnView.add(mntmDisplayTestReport);
		
		JMenu mnHelp = new JMenu("Help");
		menuBar.add(mnHelp);
		
		JMenuItem mntmAboutPivCard = new JMenuItem(c.getDisplayAboutDialogAction());
		mnHelp.add(mntmAboutPivCard);
		
		JMenuItem mntmShowDebugWindow = new JMenuItem(c.getShowDebugWindowAction());
		ImageIcon debugIcon = c.getActionIcon("application_xp_terminal", "Debug");
		mntmShowDebugWindow.setIcon(debugIcon);
		mnHelp.add(mntmShowDebugWindow);
		
		m_mainFrame.getContentPane().add(new GuiRunnerToolbar(), BorderLayout.NORTH);
		
		m_mainContent = new MainWindowContentPane();
		m_mainFrame.getContentPane().add(m_mainContent.getSplitPane(), BorderLayout.CENTER);
		
		

		m_debugFrame = new DebugWindow("Debugging Tools");
		m_debugFrame.setTitle("Debugging Tools");
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

	public MainWindowContentPane getMainContent() {
		return m_mainContent;
	}
}
