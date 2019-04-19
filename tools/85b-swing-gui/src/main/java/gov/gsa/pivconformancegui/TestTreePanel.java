package gov.gsa.pivconformancegui;

import java.awt.BorderLayout;
import java.awt.LayoutManager;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;

import gov.gsa.conformancelib.configuration.ConfigurationException;
import gov.gsa.conformancelib.configuration.ConformanceTestDatabase;
import gov.gsa.conformancelib.configuration.TestCaseModel;
import gov.gsa.conformancelib.configuration.TestStepModel;

public class TestTreePanel extends JPanel {
	
	List<TestCaseModel> m_testCases;
	DefaultTreeModel m_treeModel;
	Map<String, TestCaseTreeNode> m_testCaseDict;

	public List<TestCaseModel> getTestCases() {
		return m_testCases;
	}

	public void setTestCases(List<TestCaseModel> testCases) {
		m_testCases = testCases;
	}

	public TestTreePanel() {
		m_testCases = new ArrayList<TestCaseModel>();
		setLayout(new BorderLayout());
		TestCaseTreeNode root = new TestCaseTreeNode(null);
		createNodes(root);
		m_treeModel = new DefaultTreeModel(root);
		JTree treeControl = new JTree(m_treeModel);
		treeControl.setRootVisible(false);
		treeControl.setCellRenderer(new TestCaseTreeCellRenderer());
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.getViewport().add(treeControl);
		this.add(scrollPane, BorderLayout.CENTER);
				
	}
	
	TestCaseTreeNode getNodeByName(String name) {
		TestCaseTreeNode rv = m_testCaseDict.get(name);
		return rv;
	}
	
	TestCaseTreeNode getRootNode() {
		return (TestCaseTreeNode) m_treeModel.getRoot();
	}
	
	public void refresh() {
		GuiRunnerAppController c = GuiRunnerAppController.getInstance();
		ConformanceTestDatabase db = c.getTestDatabase();
		if(db == null) {
			DefaultMutableTreeNode root = (DefaultMutableTreeNode) m_treeModel.getRoot();
			root.removeAllChildren();
			m_treeModel.nodeStructureChanged(root);
			return;
		}
		
		try {
			m_testCases = db.getTestCases();
			m_testCaseDict = new HashMap<String, TestCaseTreeNode>();
		}catch(ConfigurationException e) {
			m_testCases = null;
		}
		TestCaseTreeNode root = (TestCaseTreeNode) m_treeModel.getRoot();
		createNodes(root);
		m_treeModel.nodeStructureChanged(root);
	}
	
    public DefaultTreeModel getTreeModel() {
		return m_treeModel;
	}

	public void setTreeModel(DefaultTreeModel treeModel) {
		m_treeModel = treeModel;
	}

	private void createNodes(DefaultMutableTreeNode top) {
    	top.removeAllChildren();
    	if(m_testCases == null) {
    		return;
    	}
    	for(TestCaseModel tc : m_testCases) {
    		TestCaseTreeNode tcNode = new TestCaseTreeNode(tc);
    		m_testCaseDict.put(tc.getIdentifier(), tcNode);
    		top.add(tcNode);
    		for(TestStepModel ts : tc.getSteps()) {
    			TestStepTreeNode tsNode = new TestStepTreeNode(ts);
    			tcNode.add(tsNode);
    		}
    	}
    }
}
