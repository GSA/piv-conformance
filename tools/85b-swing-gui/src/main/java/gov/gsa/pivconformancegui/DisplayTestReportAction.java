package gov.gsa.pivconformancegui;

import java.awt.Desktop;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;

import javax.swing.AbstractAction;
import javax.swing.Icon;
import javax.swing.JDialog;
import javax.swing.JOptionPane;

import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import ch.qos.logback.core.rolling.RollingFileAppender;
import gov.gsa.conformancelib.utilities.Csv2Html;

public class DisplayTestReportAction extends AbstractAction {

	public DisplayTestReportAction(String name, Icon icon, String toolTip) {
		super(name, icon);
		putValue(SHORT_DESCRIPTION, toolTip);
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		
		RollingFileAppender<?> csvAppender = null;
		Logger testResultsLogger = (Logger) LoggerFactory.getLogger("gov.gsa.pivconformance.testResults");
		if(testResultsLogger == null) {
			JOptionPane msgBox = new JOptionPane("Unable to get CSV logger.", JOptionPane.ERROR_MESSAGE);
			JDialog dialog = msgBox.createDialog(GuiRunnerAppController.getInstance().getMainFrame(), "Error");
			dialog.setAlwaysOnTop(true);
			dialog.setVisible(true);
		} else {
			Appender<ILoggingEvent> a = testResultsLogger.getAppender("CONFORMANCELOG");
			if(a == null) {
				JOptionPane msgBox = new JOptionPane("Unable to get CSV logger.", JOptionPane.ERROR_MESSAGE);
				JDialog dialog = msgBox.createDialog(GuiRunnerAppController.getInstance().getMainFrame(), "Error");
				dialog.setAlwaysOnTop(true);
				dialog.setVisible(true);
			}
			csvAppender = (RollingFileAppender<?>) a;
		}
		if(csvAppender != null) {
			String fn = csvAppender.getFile();
			String rfn = fn + ".html";
			try {
				PrintStream writer  = new PrintStream(rfn);
				Csv2Html.generateHtml(fn, writer, true);
				writer.close();
			} catch (FileNotFoundException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			File htmlFile = new File(rfn);
			try {
				Desktop.getDesktop().browse(htmlFile.toURI());
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}

	}

}
