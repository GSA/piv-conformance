package gov.gsa.pivconformancegui;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;

import javax.swing.AbstractAction;
import javax.swing.Box;
import javax.swing.Icon;
import javax.swing.JSplitPane;

public class ToggleTestTreeAction extends AbstractAction {

	JSplitPane m_splitPane;
	SimpleTestExecutionPanel m_testPane;

	public ToggleTestTreeAction(String name, Icon icon, String toolTip) {
		super(name, icon);
		putValue(SHORT_DESCRIPTION, toolTip);
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		GuiRunnerAppController c = GuiRunnerAppController.getInstance();
		m_splitPane = c.getApp().getMainContent().getSplitPane();
		m_testPane = c.getApp().getMainContent().getTestExecutionPanel();
		if(m_splitPane.isVisible()) {
			m_splitPane.setVisible(false);
			c.getApp().getMainContent().remove(m_splitPane);
			c.getApp().getMainFrame().add(m_testPane, BorderLayout.CENTER);
		} else {
			m_splitPane.setVisible(true);
			c.getApp().getMainFrame().remove(m_testPane);
			c.getApp().getMainFrame().add(m_splitPane, BorderLayout.CENTER);
		}
	}

}
