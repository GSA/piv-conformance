package gov.gsa.pivconformancegui;

import java.awt.event.ActionEvent;
import javax.swing.AbstractAction;
import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.conformancelib.configuration.ConfigurationException;
import gov.gsa.conformancelib.configuration.ConformanceTestDatabase;

public class OpenDefaultPIVDatabaseAction extends AbstractAction {

	private static final long serialVersionUID = 5239821601447026620L;
	private static final Logger s_logger = LoggerFactory.getLogger(OpenDefaultPIVDatabaseAction.class);
	
	public OpenDefaultPIVDatabaseAction(String name) {
		super(name);
	}
	
	public OpenDefaultPIVDatabaseAction(String name, ImageIcon icon, String toolTip) {
		super(name, icon);
		putValue(SHORT_DESCRIPTION, toolTip);
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		JFrame mainFrame = GuiRunnerAppController.getInstance().getMainFrame();
		String fullPath = "PIV_Production_Cards.db";
		try {
			ConformanceTestDatabase db = new ConformanceTestDatabase(null);
			db.openDatabaseInFile(fullPath);
			GuiRunnerAppController.getInstance().setTestDatabase(db);

			if(db != null) GuiRunnerAppController.getInstance().getApp().getMainContent().getTestExecutionPanel().getDatabaseNameField().setText(fullPath);
			
		} catch(ConfigurationException ce) {
			s_logger.error("Failed to open conformance test database from {}", fullPath);
			JOptionPane.showMessageDialog(mainFrame, "Unable to open test database");
		}
	}

}
