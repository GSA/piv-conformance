package gov.gsa.pivconformancegui;

import java.awt.event.ActionEvent;

import javax.swing.AbstractAction;
import javax.swing.Icon;

public class ShowOidDialogAction extends AbstractAction {

	public ShowOidDialogAction(String name, Icon icon, String toolTip) {
		super(name, icon);
		putValue(SHORT_DESCRIPTION, toolTip);
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		GuiRunnerAppController.getInstance().showOidDialog();
	}

}
