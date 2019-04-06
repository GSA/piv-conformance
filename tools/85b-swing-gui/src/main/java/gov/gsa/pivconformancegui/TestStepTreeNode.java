package gov.gsa.pivconformancegui;

import javax.swing.tree.DefaultMutableTreeNode;

import gov.gsa.conformancelib.configuration.TestStepModel;

public class TestStepTreeNode extends DefaultMutableTreeNode {

	TestStepModel m_testStep;
	
	public TestStepTreeNode() {
		m_testStep = null;
	}

	public TestStepTreeNode(TestStepModel testStep) {
		super(testStep);
		m_testStep = testStep;
	}

	public TestStepTreeNode(TestStepModel testStep, boolean allowsChildren) {
		super(testStep, allowsChildren);
		if(allowsChildren) throw new IllegalArgumentException("TestStepTreeNode may not allow children");
		m_testStep = testStep;
	}

	@Override
	public String toString() {
		if(m_testStep == null) return "<null>";
		return m_testStep.getTestDescription();
	}

	public TestStepModel getTestStep() {
		return m_testStep;
	}

	public void setTestStep(TestStepModel testStep) {
		m_testStep = testStep;
	}

}
