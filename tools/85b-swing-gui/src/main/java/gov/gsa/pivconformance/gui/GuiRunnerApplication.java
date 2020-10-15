package gov.gsa.pivconformance.gui;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import gov.gsa.pivconformance.cardlib.utils.PCSCUtils;
import gov.gsa.pivconformance.conformancelib.configuration.ConformanceTestDatabase;
import gov.gsa.pivconformance.conformancelib.utilities.TestRunLogController;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import javax.swing.text.DefaultEditorKit;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class GuiRunnerApplication {

	private static final org.slf4j.Logger s_logger = LoggerFactory.getLogger(GuiRunnerApplication.class);
	private static String cctVersion = null; // "v0.2.1-beta";//TODO: get from build.version

	static {
		cctVersion = getVersion();
	}

	private JFrame m_mainFrame;
	private DebugWindow m_debugFrame;
	private GuiRunnerToolbar m_toolBar;
	private MainWindowContentPane m_mainContent;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		TestRunLogController trlc = TestRunLogController.getInstance();
		try {
			trlc.bootStrapLogging(getLogConfigFile());
		} catch (Exception e) {
			System.err.println("Unable to form the path to user log config file");
			e.printStackTrace();
		}

		// Smart card essentials1 due to Java bug
		System.setProperty("sun.security.smartcardio.t0GetResponse", "false");
		System.setProperty("sun.security.smartcardio.t1GetResponse", "false");

		Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
		    public void run() {
		        trlc.cleanup();
		    }
		}));

		EventQueue.invokeLater(new Runnable() {
			@Override
			public void run() {
				try {
					PCSCUtils.ConfigureUserProperties();
					UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
					GuiRunnerApplication window = new GuiRunnerApplication();
					GuiRunnerAppController c = GuiRunnerAppController.getInstance();
					c.setCctVersion(cctVersion);
					c.setApp(window);
					LoggerContext lc = (LoggerContext) LoggerFactory.getILoggerFactory();
					GuiDebugAppender a = new GuiDebugAppender("%date %level [%thread] %logger{10} [%file:%line] %msg%n");

					a.setContext(lc);
					a.start();
					Logger logger = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
					logger.addAppender(a);
					s_logger.debug("----------------------------------------");
					s_logger.debug("FIPS 201 CCT " + cctVersion);
					s_logger.debug("----------------------------------------");
					ConformanceTestDatabase db = new ConformanceTestDatabase(null);

					// The only action permitted is opening a database
					String dbFilename = "";

					boolean opened = false;

					c.setTestDatabase(db);
					window.m_mainContent.getTestExecutionPanel().refreshDatabaseInfo();

					window.m_mainFrame.setVisible(true);
					if(opened) {
						window.m_mainContent.getTestExecutionPanel().getDatabaseNameField().setText(dbFilename);
					}
					GuiTestExecutionController txc = GuiTestExecutionController.getInstance();
					txc.setTestRunLogController(trlc);
					txc.setTestExecutionPanel(window.m_mainContent.getTestExecutionPanel());
					txc.setTestTreePanel(window.m_mainContent.getTreePanel());
					txc.setToolBar(window.m_toolBar);

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
		m_mainFrame.setTitle("FIPS 201 Card Conformance Tool " + cctVersion);


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
			@Override
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
		
		m_toolBar = new GuiRunnerToolbar();
		m_mainFrame.getContentPane().add(m_toolBar, BorderLayout.NORTH);
		
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

	public JToolBar getToolBar() {
		return m_toolBar;
	}
	
	public void setMainFrame(JFrame mainFrame) {
		m_mainFrame = mainFrame;
	}

	public GuiTestTreePanel getTreePanel() {
		return m_mainContent.getTreePanel();
	}
	
	public boolean isDebugPaneVisible() {
		return false;
	}

	public MainWindowContentPane getMainContent() {
		return m_mainContent;
	}

	private static File getLogConfigFile() {
		File logConfigFile = new File("user_log_config.xml");
		if (logConfigFile.exists() && logConfigFile.canRead()) return logConfigFile;

		// Special handling for developer mode - when debugging from IDE
		String currentDir = System.getProperty("user.dir");
		logConfigFile = new File(currentDir + "/tools/85b-swing-gui/user_log_config.xml");
		if (!logConfigFile.exists()) s_logger.error("Unable to locate user_log_config.xml");

		return logConfigFile;
	}
	
	/**
	 * Gets the version out of the build.version file
	 * @return version string or null if an exception is thrown
	 */
	private static String getVersion() {
		String buildVersion = null;
		try {
			URL resource = GuiRunnerApplication.class.getResource("/build.version");
			System.out.println("URL resource: " + resource.getFile());
			System.out.println("URL external form: " + GuiRunnerApplication.class.getResource("/build.version").toExternalForm());
			Path buildVersionFile = Paths.get(resource.toURI()).toAbsolutePath();
			buildVersion = Files.readAllLines(buildVersionFile).get(0);
		} catch (URISyntaxException e) {
			s_logger.error("URISyntaxException: " + e.getMessage());
		} catch (IOException e) {
			s_logger.error("IOException: " + e.getMessage());	
		} catch (Exception e) {
			s_logger.error("Exception: " + e.getMessage());	
		}
		return buildVersion != null ? buildVersion : "*.*.*";
	}
}
