package gov.gsa.pivconformance.gui;

import java.awt.event.ActionEvent;
import javax.swing.AbstractAction;
import javax.swing.Icon;

/** Toggles the Testing tab's tree without reparenting the application workspace. */
public class GuiToggleTestTreeAction extends AbstractAction {
    private static final long serialVersionUID = 1L;
    public GuiToggleTestTreeAction(String name, Icon icon, String toolTip) {
        super(name, icon);
        putValue(SHORT_DESCRIPTION, toolTip);
    }
    @Override public void actionPerformed(ActionEvent event) {
        GuiRunnerAppController.getInstance().getApp().getMainContent().toggleTestTree();
    }
}
