package gov.gsa.pivconformancegui;

import java.awt.Desktop;
import java.awt.event.ActionEvent;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.swing.AbstractAction;
import javax.swing.Icon;
import javax.swing.JDialog;
import javax.swing.JOptionPane;

import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import gov.gsa.conformancelib.utilities.Csv2Html;
import gov.gsa.pivconformance.card.client.CardClientException;

public class DisplayTestReportAction extends AbstractAction {
	private static final Logger s_logger = (Logger) LoggerFactory.getLogger(DisplayTestReportAction.class);

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public DisplayTestReportAction(String name, Icon icon, String toolTip) {
		super(name, icon);
		putValue(SHORT_DESCRIPTION, toolTip);
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		TimeStampedFileAppender<?> csvAppender = TestExecutionController.getInstance().getTestRunLogGroup().getAppender("CONFORMANCELOG");
		String htmlPathName = null;
		String errorMessage = null;
		if(csvAppender == null) {
			errorMessage = "Unable to obtain CSV appender";
		} else {
			String fn = ((TimeStampedFileAppender<?>) csvAppender).getTimeStampedLogPath();
			htmlPathName = fn + ".html";
			if (!Files.isReadable(Paths.get(htmlPathName))) {
				// TODO: Swap last log file into a mostRecentLog slot in the controller
				fn = fetchFromLastLog(".lastLog" + "-" + csvAppender.getName().toLowerCase());
				if (fn == null) {
					errorMessage = String.format("Couldn't extract last log file from {}", fn);
				} else {
					htmlPathName = fn + ".html";
				}
				
				if (errorMessage != null) {
					
					try {
						PrintStream writer  = new PrintStream(htmlPathName);
						Csv2Html.generateHtml(fn, writer, true);
						writer.close();
					} catch (Exception e1) {
						errorMessage = String.format("Error generating HTML output: {}", e1.getMessage());
					}
					
					File htmlFile = new File(htmlPathName);
					try {
						Desktop.getDesktop().browse(htmlFile.toURI());
					} catch (IOException e1) {
						errorMessage = String.format("Error displaying HTML output: {}", e1.getMessage());
					}
				} else {
					JOptionPane msgBox = new JOptionPane(errorMessage, JOptionPane.ERROR_MESSAGE);
					JDialog dialog = msgBox.createDialog(GuiRunnerAppController.getInstance().getMainFrame(), "Error");
					dialog.setAlwaysOnTop(true);
					dialog.setVisible(true);
				}
			}

		}
	}
	
	/**
	 * Gets the last known log file from a persistent file, .lastLog-[appendername]
	 * @param name
	 * @return
	 */
	
	private String fetchFromLastLog(String name) {
		String fileName = null;
		try (BufferedReader br = new BufferedReader(new FileReader(name))) {
		    while ((fileName = br.readLine()) != null) {
		    	;
		    }
		} catch (Exception e) {
			s_logger.error("Can't open {}", name);
		}
		return fileName;
	}
}
