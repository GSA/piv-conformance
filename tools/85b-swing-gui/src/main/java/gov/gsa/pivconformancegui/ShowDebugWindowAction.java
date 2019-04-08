package gov.gsa.pivconformancegui;

import java.awt.event.ActionEvent;

import javax.swing.AbstractAction;
import javax.swing.Icon;

public class ShowDebugWindowAction extends AbstractAction {

	public ShowDebugWindowAction() {
		
	}

	public ShowDebugWindowAction(String name) {
		super(name);
		
	}

	public ShowDebugWindowAction(String name, Icon icon) {
		super(name, icon);
		
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		GuiRunnerAppController.getInstance().showDebugWindow();
	}

}
