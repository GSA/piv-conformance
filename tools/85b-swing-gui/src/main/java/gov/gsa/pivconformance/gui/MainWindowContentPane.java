package gov.gsa.pivconformance.gui;

import java.awt.Dimension;
import java.awt.BorderLayout;

import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JLabel;
import javax.swing.BorderFactory;
import javax.swing.SwingConstants;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MainWindowContentPane extends JPanel {
	
	private static final long serialVersionUID = 7097055135183384966L;

	private static final Logger s_logger = LoggerFactory.getLogger(MainWindowContentPane.class);
	
	private GuiTestTreePanel m_treePanel;
	private JSplitPane m_splitPane;
	private SimpleTestExecutionPanel m_testExecutionPanel;
	private JTabbedPane m_tabs;
	private ResultsPanel m_resultsPanel;
	private JLabel m_version;
	
	public MainWindowContentPane() {
		this(GuiRunnerAppController.getInstance().getCctVersion());
	}

	MainWindowContentPane(String version) {
		initialize();
		m_version.setText(version == null ? "" : "CCT " + version);
	}
	
	private void initialize() {
		setLayout(new BorderLayout());
		m_treePanel = new GuiTestTreePanel();
		m_treePanel.setMinimumSize(new Dimension(300,400));
		m_testExecutionPanel = new SimpleTestExecutionPanel();
		m_testExecutionPanel.setMinimumSize(new Dimension(600,400));
		m_splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, m_treePanel, m_testExecutionPanel);
		m_splitPane.setDividerLocation(150);
		m_resultsPanel = new ResultsPanel(GuiRunnerAppController.getInstance().getPackageResultsAction(), this::showTesting);
		m_tabs = new JTabbedPane();
		m_tabs.addTab("Testing", m_splitPane);
		add(m_tabs, BorderLayout.CENTER);
		m_version = new JLabel("", SwingConstants.RIGHT);
		m_version.setFont(CctUi.font(11, java.awt.Font.PLAIN));
		m_version.setForeground(CctUi.MUTED);
		m_version.setBorder(BorderFactory.createEmptyBorder(6, 22, 8, 22));
		m_version.getAccessibleContext().setAccessibleName("CCT application version");
		JPanel footer = new JPanel(new BorderLayout());
		footer.setBackground(CctUi.CANVAS);
		footer.add(m_version, BorderLayout.EAST);
		add(footer, BorderLayout.SOUTH);
	}

	void setCompletedRun(CompletedTestRun run) {
		if (run == null) showTesting();
		m_resultsPanel.setCompletedRun(run);
		if (run != null && run.getResults() != null) {
			if (m_tabs.indexOfComponent(m_resultsPanel) < 0) m_tabs.addTab("Results", m_resultsPanel);
		} else m_tabs.remove(m_resultsPanel);
	}

	void showResults() { if (m_tabs.indexOfComponent(m_resultsPanel) >= 0) m_tabs.setSelectedComponent(m_resultsPanel); }
	void showTesting() { m_tabs.setSelectedIndex(0); }
	void toggleTestTree() {
		if (m_splitPane.getLeftComponent() == null) {
			m_splitPane.setLeftComponent(m_treePanel);
			m_splitPane.setDividerLocation(300);
		} else m_splitPane.setLeftComponent(null);
	}

	public GuiTestTreePanel getTreePanel() {
		return m_treePanel;
	}

	public void setTreePanel(GuiTestTreePanel treePanel) {
		m_treePanel = treePanel;
	}

	public SimpleTestExecutionPanel getTestExecutionPanel() {
		return m_testExecutionPanel;
	}

	public void setTestExecutionPanel(SimpleTestExecutionPanel testExecutionPanel) {
		m_testExecutionPanel = testExecutionPanel;
	}

	public JSplitPane getSplitPane() {
		return m_splitPane;
	}
}
