package gov.gsa.pivconformance.gui;

import java.net.URL;

import javax.swing.ImageIcon;
import javax.swing.JToolBar;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GuiRunnerToolbar extends JToolBar {
	
	private static final long serialVersionUID = -8973654214193169024L;
	private static final Logger s_logger = LoggerFactory.getLogger(GuiRunnerToolbar.class);
	
	public GuiRunnerToolbar() {
		super("GSA FIPS 201 Conformance GUI Runner");
		addButtons();				
	}
	
	protected void addButtons() {
		GuiRunnerAppController c = GuiRunnerAppController.getInstance();
	    this.add(c.getOpenDatabaseAction());
	    
	    this.addSeparator();
	    this.add(c.getRunAllTestsAction());
	    
	    this.addSeparator();
	    this.add(c.getShowDebugWindowAction());
	    this.addSeparator();
	    this.add(c.getDisplayTestReportAction());
	    this.addSeparator();
	    this.add(c.getOpenDefaultPIVDatabaseAction());
	    this.addSeparator();
	    this.add(c.getOpenDefaultPIVIDatabaseAction());
	    
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
