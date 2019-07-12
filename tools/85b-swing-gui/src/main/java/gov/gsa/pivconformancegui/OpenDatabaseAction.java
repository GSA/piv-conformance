package gov.gsa.pivconformancegui;

import java.awt.event.ActionEvent;
import java.io.File;

import javax.swing.AbstractAction;
import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.conformancelib.configuration.ConfigurationException;
import gov.gsa.conformancelib.configuration.ConformanceTestDatabase;

public class OpenDatabaseAction extends AbstractAction {

	private static final long serialVersionUID = 5239821601447026620L;
	private static final Logger s_logger = LoggerFactory.getLogger(OpenDatabaseAction.class);
	
	public OpenDatabaseAction(String name) {
		super(name);
	}
	
	public OpenDatabaseAction(String name, ImageIcon icon, String toolTip) {
		super(name, icon);
		putValue(SHORT_DESCRIPTION, toolTip);
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		JFileChooser fc = new JFileChooser();
		File cwd = new File(System.getProperty("user.dir"));
		fc.setCurrentDirectory(cwd);
		FileNameExtensionFilter filter = new FileNameExtensionFilter("PIV Card Conformance Tool databases (*.db)", "db");
		fc.addChoosableFileFilter(filter);
		fc.setAcceptAllFileFilterUsed(true);
		JFrame mainFrame = GuiRunnerAppController.getInstance().getMainFrame();
		int result = fc.showOpenDialog(mainFrame);
		if(result == JFileChooser.APPROVE_OPTION) {
			String fullPath = fc.getSelectedFile().getPath();
			try {
				ConformanceTestDatabase db = new ConformanceTestDatabase(null);
				db.openDatabaseInFile(fullPath);
				GuiRunnerAppController.getInstance().setTestDatabase(db);

				//GuiRunnerAppController.getInstance().getApp().getMainContent().getTestExecutionPanel().refreshDatabaseInfo();
				if(db != null) GuiRunnerAppController.getInstance().getApp().getMainContent().getTestExecutionPanel().getDatabaseNameField().setText(fullPath);
				
			} catch(ConfigurationException ce) {
				s_logger.error("Failed to open conformance test database from {}", fullPath);
				JOptionPane.showMessageDialog(mainFrame, "Unable to open test database");
			}
		}
	}

}
