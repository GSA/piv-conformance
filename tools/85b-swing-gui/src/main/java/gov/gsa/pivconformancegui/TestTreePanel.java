package gov.gsa.pivconformancegui;

import java.awt.BorderLayout;
import java.awt.LayoutManager;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;

import gov.gsa.conformancelib.configuration.TestCaseModel;
import gov.gsa.conformancelib.configuration.TestStepModel;

public class TestTreePanel extends JPanel {
	
	List<TestCaseModel> m_testCases;
	DefaultTreeModel m_treeModel;

	public List<TestCaseModel> getTestCases() {
		return m_testCases;
	}

	public void setTestCases(List<TestCaseModel> testCases) {
		m_testCases = testCases;
	}

	public TestTreePanel() {
		m_testCases = new ArrayList<TestCaseModel>();
		setLayout(new BorderLayout());
		DefaultMutableTreeNode root = new DefaultMutableTreeNode("root");
		createNodes(root);
		m_treeModel = new DefaultTreeModel(root);
		JTree treeControl = new JTree(m_treeModel);
		treeControl.setRootVisible(false);
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.getViewport().add(treeControl);
		this.add(scrollPane, BorderLayout.CENTER);
				
	}
	
	public void refresh() {
		GuiRunnerAppController c = GuiRunnerAppController.getInstance();
		m_testCases = c.getTestDatabase().getTestCases();
		DefaultMutableTreeNode root = (DefaultMutableTreeNode) m_treeModel.getRoot();
		createNodes(root);
		m_treeModel.nodeStructureChanged(root);
	}
	
    private void createNodes(DefaultMutableTreeNode top) {
    	top.removeAllChildren();
    	for(TestCaseModel tc : m_testCases) {
    		TestCaseTreeNode tcNode = new TestCaseTreeNode(tc);
    		top.add(tcNode);
    		for(TestStepModel ts : tc.getSteps()) {
    			TestStepTreeNode tsNode = new TestStepTreeNode(ts);
    			tcNode.add(tsNode);
    		}
    	}
    }
}
