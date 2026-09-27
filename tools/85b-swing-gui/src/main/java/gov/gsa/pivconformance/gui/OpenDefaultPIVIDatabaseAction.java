package gov.gsa.pivconformance.gui;

import java.awt.event.ActionEvent;
import javax.swing.AbstractAction;
import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.pivconformance.conformancelib.configuration.ConfigurationException;
import gov.gsa.pivconformance.conformancelib.configuration.ConformanceTestDatabase;

public class OpenDefaultPIVIDatabaseAction extends AbstractAction {

	private static final long serialVersionUID = 5239821601447026620L;
	private static final Logger s_logger = LoggerFactory.getLogger(OpenDefaultPIVIDatabaseAction.class);
	
	public OpenDefaultPIVIDatabaseAction(String name) {
		super(name);
	}
	
	public OpenDefaultPIVIDatabaseAction(String name, ImageIcon icon, String toolTip) {
		super(name, icon);
		putValue(SHORT_DESCRIPTION, toolTip);
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		JFrame mainFrame = GuiRunnerAppController.getInstance().getMainFrame();
		try {
			String fullPath = CctApplicationPaths.requireResource("PIV-I_Production_Cards.db").toString();
			ConformanceTestDatabase db = new ConformanceTestDatabase(null);
			db.openDatabaseInFile(fullPath);
			GuiRunnerAppController.getInstance().setTestDatabase(db);

			if(db != null) GuiRunnerAppController.getInstance().getApp().getMainContent().getTestExecutionPanel().getDatabaseNameField().setText(fullPath);
			
		} catch(ConfigurationException | IllegalStateException ce) {
			s_logger.error("Failed to open the default PIV-I conformance test database", ce);
			JOptionPane.showMessageDialog(mainFrame, "Unable to open test database");
		}
	}

}
