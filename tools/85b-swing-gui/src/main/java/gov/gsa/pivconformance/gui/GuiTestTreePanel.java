package gov.gsa.pivconformance.gui;

import java.awt.BorderLayout;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;

import gov.gsa.pivconformance.conformancelib.configuration.ConfigurationException;
import gov.gsa.pivconformance.conformancelib.configuration.ConformanceTestDatabase;
import gov.gsa.pivconformance.conformancelib.configuration.TestCaseModel;
import gov.gsa.pivconformance.conformancelib.configuration.TestStepModel;

public class GuiTestTreePanel extends JPanel {
	// TODO: Look at tooltips here
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	List<TestCaseModel> m_testCases;
	DefaultTreeModel m_treeModel;
	Map<String, GuiTestCaseTreeNode> m_testCaseDict;

	public List<TestCaseModel> getTestCases() {
		return m_testCases;
	}

	public void setTestCases(List<TestCaseModel> testCases) {
		m_testCases = testCases;
	}

	public GuiTestTreePanel() {
		m_testCases = new ArrayList<TestCaseModel>();
		setLayout(new BorderLayout());
		GuiTestCaseTreeNode root = new GuiTestCaseTreeNode(null);
		createNodes(root);
		m_treeModel = new DefaultTreeModel(root);
		JTree treeControl = new JTree(m_treeModel);
		ToolTipManager.sharedInstance().registerComponent(treeControl);
		treeControl.setRootVisible(false);
		treeControl.setCellRenderer(new TestCaseTreeCellRenderer());
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.getViewport().add(treeControl);
		this.add(scrollPane, BorderLayout.CENTER);
				
	}
	
	GuiTestCaseTreeNode getNodeByName(String name) {
		GuiTestCaseTreeNode rv = m_testCaseDict.get(name);
		return rv;
	}
	
	GuiTestCaseTreeNode getRootNode() {
		return (GuiTestCaseTreeNode) m_treeModel.getRoot();
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
			m_testCaseDict = new HashMap<String, GuiTestCaseTreeNode>();
		}catch(ConfigurationException e) {
			m_testCases = null;
		}
		GuiTestCaseTreeNode root = (GuiTestCaseTreeNode) m_treeModel.getRoot();
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
    		GuiTestCaseTreeNode tcNode = new GuiTestCaseTreeNode(tc);
    		m_testCaseDict.put(tc.getIdentifier(), tcNode);
    		top.add(tcNode);
    		for(TestStepModel ts : tc.getSteps()) {
    			GuiTestStepTreeNode tsNode = new GuiTestStepTreeNode(ts);
    			tcNode.add(tsNode);
    		}
    	}
    }
}
