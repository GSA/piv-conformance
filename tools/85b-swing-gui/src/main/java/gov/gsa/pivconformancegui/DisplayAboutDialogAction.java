package gov.gsa.pivconformancegui;

import java.awt.event.ActionEvent;

import javax.swing.AbstractAction;
import javax.swing.Icon;

public class DisplayAboutDialogAction extends AbstractAction{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public DisplayAboutDialogAction(String name, Icon icon, String toolTip) {
		super(name, icon);
		putValue(SHORT_DESCRIPTION, toolTip);
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		GuiRunnerAppController.getInstance().showAboutDialog();
	}

}
