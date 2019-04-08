package gov.gsa.pivconformancegui;

import java.net.URL;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JToolBar;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GuiRunnerToolbar extends JToolBar {
	
	private static final long serialVersionUID = -8973654214193169024L;
	private static final Logger s_logger = LoggerFactory.getLogger(GuiRunnerToolbar.class);
	
	public GuiRunnerToolbar() {
		super("85b GUI Runner");
		addButtons();				
	}
	
	protected void addButtons() {
		ImageIcon openIcon = getToolbarIcon("folder", "Open");
		OpenDatabaseAction openAction = new OpenDatabaseAction("Open Database", openIcon, "Open a conformance test database");
	    this.add(openAction);
	    
	    this.addSeparator();
	    ImageIcon runIcon = getToolbarIcon("building_go", "Run");
	    RunAllTestsAction runAction = new RunAllTestsAction("Run all tests", runIcon, "Run all available tests in database");
	    this.add(runAction);
	    
	    this.addSeparator();
	    ImageIcon debugIcon = getToolbarIcon("application_xp_terminal", "Debug");
	    ShowDebugWindowAction debugAction = new ShowDebugWindowAction("Show Debugging tools", debugIcon, "Show detailed log and debugging tools");
	    this.add(debugAction);
	    
	}
	
	protected ImageIcon getToolbarIcon(String imageName, String altText) {
		String imgLocation = "/icons/" + imageName + ".png";
		URL imageUrl = GuiRunnerToolbar.class.getResource(imgLocation);
		if(imageUrl == null) {
			s_logger.error("Unable to get image at classpath location {}", imgLocation);
			return null;
		}
		return new ImageIcon(imageUrl, altText);
	}

}
