package gov.gsa.pivconformancegui;

import java.awt.Component;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import javax.swing.ImageIcon;
import javax.swing.JTree;
import javax.swing.tree.DefaultTreeCellRenderer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.conformancelib.configuration.TestCaseModel;
import gov.gsa.conformancelib.configuration.TestStatus;
import gov.gsa.conformancelib.configuration.TestStepModel;

public class TestCaseTreeCellRenderer extends DefaultTreeCellRenderer {
	
	private static final long serialVersionUID = -7279235468508117069L;
    private static final Logger s_logger = LoggerFactory.getLogger(TestCaseTreeCellRenderer.class);
    
    private static Map<TestStatus, ImageIcon> s_statusIcons;
    
    static {
    	s_statusIcons = new HashMap<TestStatus, ImageIcon>();
    	for(TestStatus s : TestStatus.values()) {
    		switch(s) {
				case SKIP:
				{
					ImageIcon icon = getStatusIcon("error_go");
					s_statusIcons.put(s, icon);
					break;
				}
				case FAIL:
				{
					ImageIcon icon = getStatusIcon("cross");
					s_statusIcons.put(s, icon);
					break;
				}
				case PASS:
				{
					ImageIcon icon = getStatusIcon("accept");
					s_statusIcons.put(s, icon);
					break;
				}
				default:
				{
					s_logger.error("Setting {} to page", s);
					ImageIcon icon = getStatusIcon("page");
					s_statusIcons.put(s, icon);
					break;
				}
    		}
    	}
    }
    
    // page = none
	// accept = pass
	// cross = fail
	// error_go = skip

	@Override
	public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel, boolean expanded, boolean leaf,
			int row, boolean hasFocus) {
		super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);
		TestStatus status = TestStatus.NONE;
		if(value instanceof TestCaseTreeNode) {
			TestCaseTreeNode node = (TestCaseTreeNode)value;
			TestCaseModel test = node.getTestCase();
			if(test != null) status = test.getTestStatus();
		} else if(value instanceof TestStepTreeNode) {
			TestStepTreeNode node = (TestStepTreeNode)value;
			TestStepModel step = node.getTestStep();
			if(step != null) status = step.getTestStatus();
		}
		ImageIcon icon = s_statusIcons.get(status);
		if(icon != null) {
			setIcon(icon);
			//s_logger.info("Got {} for {}", icon.getDescription(), status);
		} else {
			s_logger.error("icon was null for tree node");
		}
		return this;
	}

	public TestCaseTreeCellRenderer() {
	}
	
	protected static ImageIcon getStatusIcon(String imageName) {
		String imgLocation = "/icons/" + imageName + ".png";
		URL imageUrl = GuiRunnerAppController.class.getResource(imgLocation);
		if(imageUrl == null) {
			s_logger.error("Unable to get image at classpath location {}", imgLocation);
			return null;
		}
		return new ImageIcon(imageUrl, imgLocation);
	}

}
