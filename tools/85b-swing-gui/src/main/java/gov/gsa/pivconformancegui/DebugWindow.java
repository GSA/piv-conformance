package gov.gsa.pivconformancegui;

import java.awt.HeadlessException;

import javax.swing.JFrame;
import javax.swing.JTabbedPane;
import javax.swing.JTextPane;

import java.awt.BorderLayout;

public class DebugWindow extends JFrame {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	RawLogPanel m_logPane;

	public DebugWindow() throws HeadlessException {
		this("");
	}

	public DebugWindow(String title) throws HeadlessException {	
		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		getContentPane().add(tabbedPane, BorderLayout.CENTER);
		m_logPane = new RawLogPanel();
		tabbedPane.addTab("Log View", m_logPane);
		UtilitiesPane up = new UtilitiesPane();
		tabbedPane.addTab("Utilities", up);
	}
	
	public JTextPane getDebugTextPane() {
		return m_logPane.getDebugTextPane();
	}
}
