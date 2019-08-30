package gov.gsa.pivconformancegui;

import java.awt.event.ActionEvent;

import javax.swing.AbstractAction;
import javax.swing.ImageIcon;

public class RunAllTestsAction extends AbstractAction {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public RunAllTestsAction(String name) {
		super(name);
	}
	
	public RunAllTestsAction(String name, ImageIcon icon, String toolTip) {
		super(name, icon);
		putValue(SHORT_DESCRIPTION, toolTip);
	}
	
	@Override
	public void actionPerformed(ActionEvent e) {
			// stubbed out until the controller is fixed
	}

}
