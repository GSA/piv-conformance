/**
 * 
 */
package gov.gsa.pivconformancegui;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.core.joran.spi.JoranException;
import ch.qos.logback.core.util.StatusPrinter;

/**
 * Class that consolidates the four appenders into a single disposable group
 *
 */
public class TestRunLogGroup {
	private static final org.slf4j.Logger s_logger = LoggerFactory.getLogger(GuiRunnerApplication.class);
	/*
	 * Note that these names MUST match the user_log_config.xml appender names.
	 * start time, end time, log file path name.  It instantiates and destroys
	 * appenders as a group, but is ephemeral, so we can re-create a group
	 * each run.
	 */
	static final HashMap<String,String> m_loggers = null;
	static {
		m_loggers.put("CONFORMANCELOG", "gov.gsa.pivconformance.testResults");
		m_loggers.put("APDULOG", "gov.gsa.pivconformance.apdu");
	}
	
	private HashMap<String, TimeStampedFileAppender<?>> m_appenders = null;
	private String m_timeStampedLogPath = null;
	private Date m_startTime = null;
	private Date m_stopTime = null;
	
	public TestRunLogGroup() {
		/*
		 * 
		 *
		 **/
		this.initialize();
	}
	
	void initialize() {
		// Set up all of the loggers
		LoggerContext ctx = (LoggerContext) LoggerFactory.getILoggerFactory();
		TimeStampedFileAppender<?> csvAppender = null;
		try {
			File logConfigFile = new File("user_log_config.xml");
			if(logConfigFile.exists() && logConfigFile.canRead()) {
				JoranConfigurator configurator = new JoranConfigurator();
				configurator.setContext(ctx);
				configurator.doConfigure(logConfigFile.getCanonicalPath());
			}
		} catch(JoranException e) {
			// handled by status printer
		} catch (IOException e) {
			System.err.println("Unable to resolve logging config to a readable file");
			e.printStackTrace();
		}
		StatusPrinter.printIfErrorsOccured(ctx);
		Map.Entry me = null;
		Iterator<?> i = m_loggers.entrySet().iterator();
		while (i.hasNext()) {
			me = (Map.Entry<String,String>) i.next();
			String loggerName = (String) me.getKey();
			Logger logger = (Logger) LoggerFactory.getLogger(loggerName);
			if (logger == null) {
				s_logger.warn("No logger was configured for {}", loggerName);
			} else 
				m_appenders.put(loggerName, (TimeStampedFileAppender<?>) logger.getAppender(loggerName));
		}
		m_startTime = new Date();
		s_logger.debug("Logging has been initialized");
	}
	
	String getTimeStampedLogPath() {
		return m_timeStampedLogPath;
	}
	
	/**
	 * Forces a timestamp based on start time and the current time
	 */
	public void setStopTime() {		
		if (m_startTime == null) {
			s_logger.warn("Test log group not started"); // TODO: Figure out what to do here. Does it matter?
		}
		
		m_stopTime = new Date();
		setTimeStamp();
	}
	
	/**
	 * Creates the path names of the timestamped copy of each configured log
	 * 
	 */
	private void setTimeStamp() {
		
		String startTs = null;
		String stopTs = null;
		
		GregorianCalendar startCal = (GregorianCalendar) Calendar.getInstance();
		startCal.setTime(m_startTime);
		GregorianCalendar endCal = (GregorianCalendar) Calendar.getInstance();
		endCal.setTime(m_stopTime);
		startTs = String.format("%04d%02d%02d_%02d%02d%02d", 
				startCal.get(Calendar.YEAR), startCal.get(Calendar.MONTH) + 1, startCal.get(Calendar.DAY_OF_MONTH),
				startCal.get(Calendar.HOUR_OF_DAY), startCal.get(Calendar.MINUTE), startCal.get(Calendar.SECOND));
		stopTs = String.format("%04d%02d%02d_%02d%02d%02d", 
				startCal.get(Calendar.YEAR), startCal.get(Calendar.MONTH + 1), startCal.get(Calendar.DAY_OF_MONTH),
				startCal.get(Calendar.HOUR_OF_DAY), startCal.get(Calendar.MINUTE), startCal.get(Calendar.SECOND));
		
		// Loop on appenders
		Map.Entry me = null;
		Iterator<?> i = m_appenders.entrySet().iterator();
		while (i.hasNext()) {
			me = (Map.Entry<String,String>) i.next();
			String logName = (String) me.getKey();
			TimeStampedFileAppender<?> a = (TimeStampedFileAppender<?>) me.getValue();
			
			// Get separators straight		
			s_logger.debug("Conformance Log CSV file path: " + this.m_appenders.get("CONFORMANCELOG").getFile());
			File testFile = new File(a.getFile()); // Normalize by instantiating a File
			s_logger.debug("System canonical path: " + testFile.getPath());
			String currPath = testFile.getPath();
			// Check whether we're in a situation where separators are different than logger config (/)
			if (testFile.getAbsolutePath().lastIndexOf("/") < 0) {
				// Windows
				currPath.replaceAll("\\\\", "/");
			}
			
			// Synchronize timestamp portion of path
			String dirName = currPath.substring(0, currPath.lastIndexOf("/"));
			String logFileName = currPath.substring(currPath.lastIndexOf("/") + 1);
			String baseName =  (startTs + "-" + stopTs + "-" + logFileName);
			s_logger.debug("Setting {} to: {}", logName, dirName + File.separator + baseName);
			a.setTimeStampedLogPath(dirName + File.separator + baseName);
			// Make the copy
			copyFile(currPath, a.getTimeStampedLogPath());
		}
	}
	
	private boolean copyFile(String oldPath, String newPath) {
		boolean rv = false;
		s_logger.debug(String.format("Copying {} to {}", oldPath, newPath));
		try {
			Files.copy(Paths.get(oldPath), Paths.get(newPath), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
		} catch (IOException e) {
			s_logger.error("IOException: " + e.getMessage());
		}
		return rv;
	}
}
