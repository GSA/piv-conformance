package gov.gsa.pivconformance.gui;

import javax.swing.tree.DefaultMutableTreeNode;

import gov.gsa.pivconformance.conformancelib.configuration.TestStepModel;

public class GuiTestStepTreeNode extends DefaultMutableTreeNode {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	TestStepModel m_testStep;
	
	public GuiTestStepTreeNode() {
		m_testStep = null;
	}

	public GuiTestStepTreeNode(TestStepModel testStep) {
		super(testStep);
		m_testStep = testStep;
	}

	public GuiTestStepTreeNode(TestStepModel testStep, boolean allowsChildren) {
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
