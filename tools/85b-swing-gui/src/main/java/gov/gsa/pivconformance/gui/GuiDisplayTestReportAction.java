package gov.gsa.pivconformance.gui;

import java.awt.Desktop;
import java.awt.event.ActionEvent;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Paths;

import javax.swing.AbstractAction;
import javax.swing.Icon;
import javax.swing.JDialog;
import javax.swing.JOptionPane;

import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Logger;
import gov.gsa.pivconformance.conformancelib.utilities.TestRunLogController;
import gov.gsa.pivconformance.conformancelib.utilities.TimeStampedFileAppender;
import gov.gsa.pivconformance.conformancelib.utilities.Csv2Html;

public class GuiDisplayTestReportAction extends AbstractAction {
	private static final Logger s_logger = (Logger) LoggerFactory.getLogger(GuiDisplayTestReportAction.class);
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public GuiDisplayTestReportAction(String name, Icon icon, String toolTip) {
		super(name, icon);
		putValue(SHORT_DESCRIPTION, toolTip);
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		String errorMessage = null;
		TestRunLogController lg = GuiTestExecutionController.getInstance().getTestRunLogController();
		if (lg != null) {
			TimeStampedFileAppender<?> csvAppender = lg.getAppender("CONFORMANCELOG");
			String htmlPathName = null;
			if (csvAppender != null) {
				String lp = csvAppender.getTimeStampedLogPath();
				if (!Files.isReadable(Paths.get(lp))) {
					String fn = fetchFromLastLog(".lastlog" + "-" + csvAppender.getName().toLowerCase());
					if (fn == null) {
						errorMessage = String.format("Couldn't extract last log file name from %s",
								".lastlog" + "-" + csvAppender.getName().toLowerCase());
					} else {
						lp = fn;
					}
				}

				if (lp != null) {
					htmlPathName = lp + ".html";
					try {
						PrintStream writer = new PrintStream(htmlPathName);
						Csv2Html.generateHtml(lp, writer, true);
						writer.close();

						File htmlFile = new File(htmlPathName);
						try {
							Desktop.getDesktop().browse(htmlFile.toURI());
						} catch (IOException e1) {
							errorMessage = String.format("Couldn't render HTML results page: %s", e1.getMessage());
						}
					} catch (Exception e1) {
						errorMessage = String.format("Coudn't generate HTML file: %s", e1.getMessage());
					}
				} else {
					errorMessage = String.format("Log %s is is not readable", lp);
				}
			} else {
				errorMessage = "Unable to get the CSV appender";
			}
		} else {
			errorMessage = "No tests have been run yet";
		}

		if (errorMessage != null) {
			JOptionPane msgBox = new JOptionPane(errorMessage, JOptionPane.ERROR_MESSAGE);
			JDialog dialog = msgBox.createDialog(GuiRunnerAppController.getInstance().getMainFrame(), "Error");
			dialog.setAlwaysOnTop(true);
			dialog.setVisible(true);
		}
	}

	/**
	 * Gets the last known log file from a persistent file,
	 * .lastlog-{appendername}.toLowerCase()
	 * 
	 * @param name
	 * @return
	 */

	private String fetchFromLastLog(String name) {
		String fileName = null;
		try (BufferedReader br = new BufferedReader(new FileReader(name))) {
			fileName = br.readLine();
		} catch (Exception e) {
			String s = TestRunLogController.getCwd("gov.gsa.pivconformance.gui.GuiRunnerApplication");
			s_logger.error("Can't open {}",
					TestRunLogController.getCwd("gov.gsa.pivconformance.gui.GuiRunnerApplication") + "/" + name);
		}
		return fileName;
	}
}
