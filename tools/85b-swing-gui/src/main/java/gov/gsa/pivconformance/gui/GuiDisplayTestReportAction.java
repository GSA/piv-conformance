package gov.gsa.pivconformance.gui;

import java.awt.event.ActionEvent;
import javax.swing.AbstractAction;
import javax.swing.Icon;

/** Selects the completed run's native Results workspace. */
public class GuiDisplayTestReportAction extends AbstractAction {
    private static final long serialVersionUID = 1L;

    public GuiDisplayTestReportAction(String name, Icon icon, String toolTip) {
        super(name, icon);
        putValue(SHORT_DESCRIPTION, toolTip);
        setEnabled(false);
    }

    @Override public void actionPerformed(ActionEvent event) {
        GuiRunnerApplication app = GuiRunnerAppController.getInstance().getApp();
        if (app != null) app.getMainContent().showResults();
    }
}
