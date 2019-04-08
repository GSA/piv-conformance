package gov.gsa.pivconformancegui;

import java.awt.event.ActionEvent;
import java.io.File;

import javax.swing.AbstractAction;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;

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

	@Override
	public void actionPerformed(ActionEvent e) {
		JFileChooser fc = new JFileChooser();
		File cwd = new File(System.getProperty("user.dir"));
		fc.setCurrentDirectory(cwd);
		JFrame mainFrame = GuiRunnerAppController.getInstance().getMainFrame();
		int result = fc.showOpenDialog(mainFrame);
		if(result == JFileChooser.APPROVE_OPTION) {
			String filename = fc.getSelectedFile().getName();
			try {
				ConformanceTestDatabase db = new ConformanceTestDatabase(null);
				db.openDatabaseInFile(filename);
				GuiRunnerAppController.getInstance().setTestDatabase(db);
			} catch(ConfigurationException ce) {
				s_logger.error("Failed to open conformance test database from {}", filename);
				JOptionPane.showMessageDialog(mainFrame, "Unable to open test database");
			}
		}
	}

}
