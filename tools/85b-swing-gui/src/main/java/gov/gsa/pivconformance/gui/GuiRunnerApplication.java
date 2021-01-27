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
import java.io.*;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import static gov.gsa.pivconformance.conformancelib.utilities.TestRunLogController.pathFixup;

public class GuiRunnerApplication {

	private static final org.slf4j.Logger s_logger = LoggerFactory.getLogger(GuiRunnerApplication.class);
	private static String cctVersion = null;

	static {
		cctVersion = getVersion("build.version");
	}

	private JFrame m_mainFrame;
	private DebugWindow m_debugFrame;
	private GuiRunnerToolbar m_toolBar;
	private MainWindowContentPane m_mainContent;

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

	/**
	 * Recursively search for a resource file
	 * @param current directory
	 * @param pattern pattern to search for
	 * @param excludePattern patterns to exclude (full path)
	 * @return File associated with the file on disk
	 */
	static File locateFile(File current, String pattern, String excludePattern) {
		File file = null;
		if (current.isDirectory()) {
			File[] fileList = current.listFiles();
			for (File f : fileList) {
				file = locateFile(f, pattern, excludePattern);
				if (file != null)
					break;
			}
		} else {
			if (!current.getAbsolutePath().toLowerCase().contains(excludePattern)) {
				if (current.getName().equals(pattern)) {
					return current;
				}
			}
		}
		return file;
	}

	private static File getResourceFile(String target, String excludePattern) {
		File resourceFile = null;
		s_logger.debug("Looking for resource:" + target);
		resourceFile = locateFile(new File("./"), target, excludePattern);
		return resourceFile;
	}

	private static String getVersion(String name) {
		String version = null;
		File resourceFile = getResourceFile("build.version", File.separator + "build" + File.separator);
		try {
			BufferedReader versionFile = new BufferedReader (new FileReader(resourceFile));
			version = versionFile.readLine();
		} catch (IOException e) {
			s_logger.error("Can't open " + name);
		}
		return version;
	}

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		String currentDirectory;
		// When running out of a jar file, args[0] is the jar?
		String path = pathFixup(GuiRunnerApplication.class.getProtectionDomain().getCodeSource().getLocation().getPath());
		try {
			if (path.endsWith(".jar")) {
				path += File.separator;
				String message = "Running from jar file";
				s_logger.debug(message);
			} else {
				String message = "Running from IDE";
				s_logger.debug(message);
			}
			currentDirectory = URLDecoder.decode(path, StandardCharsets.UTF_8);
			String message = "Current directory is " + currentDirectory;
			s_logger.debug(message);
		} catch (Exception e) {
			String message = e.getMessage();
			s_logger.error(message);
			return;
		}

		TestRunLogController trlc = TestRunLogController.getInstance();
		try {
			trlc.bootStrapLogging(getResourceFile("user_log_config.xml", File.separator + "build" + File.separator));
		} catch (Exception e) {
			System.err.println("Unable to form the path to user log config file");
			e.printStackTrace();
		}

		// Smart card essentials1 due to Java bug(s)
		System.setProperty("sun.security.smartcardio.t0GetResponse", "false");
		System.setProperty("sun.security.smartcardio.t1GetResponse", "false");
		if(System.getProperty("os.name").toLowerCase().indexOf("mac") >= 0) {
			System.setProperty("sun.security.smartcardio.library", "/System/Library/Frameworks/PCSC.framework/Versions/Current/PCSC");
		}
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
}
