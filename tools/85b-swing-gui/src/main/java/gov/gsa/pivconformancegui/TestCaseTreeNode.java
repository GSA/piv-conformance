package gov.gsa.pivconformancegui;

import javax.swing.tree.DefaultMutableTreeNode;

import gov.gsa.conformancelib.configuration.TestCaseModel;

public class TestCaseTreeNode extends DefaultMutableTreeNode {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	TestCaseModel m_testCase;

	public TestCaseModel getTestCase() {
		return m_testCase;
	}

	public void setTestCase(TestCaseModel testCase) {
		m_testCase = testCase;
	}

	public TestCaseTreeNode() {
		m_testCase = null;
	}

	public TestCaseTreeNode(TestCaseModel testCase) {
		super(testCase);
		m_testCase = testCase;
	}

	public TestCaseTreeNode(TestCaseModel testCase, boolean allowsChildren) {
		super(testCase, allowsChildren);
		m_testCase = testCase;
	}

	@Override
	public String toString() {
		if(m_testCase != null) {
			return m_testCase.getIdentifier() + " - " + m_testCase.getDescription();
		}

		return new String("(null)");
	}
	

}
