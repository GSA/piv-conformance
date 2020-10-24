package gov.gsa.pivconformance.gui;

import java.awt.event.ActionEvent;

import javax.swing.AbstractAction;
import javax.swing.Icon;

public class ShowDebugWindowAction extends AbstractAction {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public ShowDebugWindowAction() {
		
	}

	public ShowDebugWindowAction(String name) {
		super(name);
		
	}

	public ShowDebugWindowAction(String name, Icon icon, String toolTip) {
		super(name, icon);
		putValue(SHORT_DESCRIPTION, toolTip);
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		GuiRunnerAppController.getInstance().showDebugWindow();
	}

}
