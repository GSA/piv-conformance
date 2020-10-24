package gov.gsa.pivconformance.gui;

import java.awt.HeadlessException;

import javax.swing.JFrame;
import javax.swing.JTabbedPane;
import javax.swing.JTextPane;
import javax.swing.SwingConstants;

import java.awt.BorderLayout;

public class DebugWindow extends JFrame {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	GuiRawLogPanel m_logPane;

	public DebugWindow() throws HeadlessException {
		this("");
	}

	public DebugWindow(String title) throws HeadlessException {	
		JTabbedPane tabbedPane = new JTabbedPane(SwingConstants.TOP);
		getContentPane().add(tabbedPane, BorderLayout.CENTER);
		m_logPane = new GuiRawLogPanel();
		tabbedPane.addTab("Log View", m_logPane);
		UtilitiesPane up = new UtilitiesPane();
		tabbedPane.addTab("Utilities", up);
	}
	
	public JTextPane getDebugTextPane() {
		return m_logPane.getDebugTextPane();
	}
}
