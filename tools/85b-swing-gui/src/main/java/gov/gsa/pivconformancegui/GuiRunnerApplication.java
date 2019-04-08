package gov.gsa.pivconformancegui;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JMenuBar;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JRadioButtonMenuItem;

import gov.gsa.conformancelib.configuration.ConformanceTestDatabase;

import javax.swing.JPanel;
import java.awt.BorderLayout;

public class GuiRunnerApplication {

	private JFrame m_mainFrame;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					GuiRunnerApplication window = new GuiRunnerApplication();
					GuiRunnerAppController c = GuiRunnerAppController.getInstance();
					c.setApp(window);
					ConformanceTestDatabase db = new ConformanceTestDatabase(null);
					db.openDatabaseInFile("../../conformancelib/testdata/icam_test.db");
					c.setTestDatabase(db);
					window.m_mainFrame.setVisible(true);
					
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
		m_mainFrame.setBounds(100, 100, 450, 300);
		m_mainFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		
		JMenuBar menuBar = new JMenuBar();
		m_mainFrame.setJMenuBar(menuBar);
		
		JMenu mnFile = new JMenu("File");
		menuBar.add(mnFile);
		
		JMenuItem mntmOpen = new JMenuItem("Open");
		mnFile.add(mntmOpen);
		
		JMenuItem mntmExit = new JMenuItem("Exit");
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
		
		TestTreePanel panel = new TestTreePanel();
		m_mainFrame.getContentPane().add(panel, BorderLayout.WEST);
	}

	public JFrame getMainFrame() {
		return m_mainFrame;
	}

	public void setMainFrame(JFrame mainFrame) {
		m_mainFrame = mainFrame;
	}

}
