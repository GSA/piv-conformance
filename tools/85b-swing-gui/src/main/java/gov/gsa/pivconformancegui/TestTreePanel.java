package gov.gsa.pivconformancegui;

import java.awt.BorderLayout;
import java.awt.LayoutManager;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;

import gov.gsa.conformancelib.configuration.TestCaseModel;
import gov.gsa.conformancelib.configuration.TestStepModel;

public class TestTreePanel extends JPanel {
	
	List<TestCaseModel> m_testCases;

	public List<TestCaseModel> getTestCases() {
		return m_testCases;
	}

	public void setTestCases(List<TestCaseModel> testCases) {
		m_testCases = testCases;
	}

	public TestTreePanel() {
		setLayout(new BorderLayout());
		JTree treeControl = new JTree();
		treeControl.setRootVisible(false);
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.getViewport().add(treeControl);
		this.add(scrollPane, BorderLayout.CENTER);
		m_testCases = new ArrayList<TestCaseModel>();
	}
	
    private void createNodes(DefaultMutableTreeNode top) {
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
