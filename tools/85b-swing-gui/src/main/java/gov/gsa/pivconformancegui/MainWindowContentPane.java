package gov.gsa.pivconformancegui;

import java.awt.Dimension;

import javax.swing.JPanel;
import javax.swing.JSplitPane;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MainWindowContentPane extends JPanel {
	
	private static final long serialVersionUID = 7097055135183384966L;

	private static final Logger s_logger = LoggerFactory.getLogger(MainWindowContentPane.class);
	
	private GuiTestTreePanel m_treePanel;
	private JSplitPane m_splitPane;
	private SimpleTestExecutionPanel m_testExecutionPanel;
	
	public MainWindowContentPane() {
		initialize();
	}
	
	private void initialize() {
		m_treePanel = new GuiTestTreePanel();
		m_treePanel.setMinimumSize(new Dimension(300,400));
		m_testExecutionPanel = new SimpleTestExecutionPanel();
		m_testExecutionPanel.setMinimumSize(new Dimension(600,400));
		m_splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, m_treePanel, m_testExecutionPanel);
		m_splitPane.setDividerLocation(150);
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
