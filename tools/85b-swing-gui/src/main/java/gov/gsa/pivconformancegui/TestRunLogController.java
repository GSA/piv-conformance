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
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import ch.qos.logback.core.joran.spi.JoranException;
import ch.qos.logback.core.util.StatusPrinter;

/**
 * Class that consolidates the four appenders into a single disposable group
 *
 */
public class TestRunLogController {
	private static final org.slf4j.Logger s_logger = LoggerFactory.getLogger(TestRunLogController.class);
	/*
	 * Note that these names MUST match the user_log_config.xml appender names.
	 * start time, end time, log file path name.  It instantiates and destroys
	 * appenders as a group, but is ephemeral, so we can re-create a group
	 * each run.
	 */
	static final HashMap<String,String> m_loggers = new HashMap<String,String>() {
		static final long serialVersionUID = 1L;
		{
			put("CONFORMANCELOG", "gov.gsa.pivconformance.testResults");
			put("APDULOG", "gov.gsa.pivconformance.apdu");
		}
	};
	
	private HashMap<String, TimeStampedFileAppender<?>> m_appenders = null;
	private boolean m_initialized = false;
	private String m_timeStampedLogPath = null;
	private Date m_startTime = null;
	private Date m_stopTime = null;
	
	public TestRunLogController(LoggerContext ctx) {
		try {
			System.out.println("Working Directory = " +
		              System.getProperty("user.dir"));
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
		this.initialize(ctx);
	}
	
	void initialize(LoggerContext ctx) {
		m_appenders = new HashMap<String,TimeStampedFileAppender<?>>();
		
		// Bootstrap the Logging
		LoggerContext lc = (LoggerContext) LoggerFactory.getILoggerFactory();
		Appender<ILoggingEvent> a = new GuiDebugAppender("%date %level [%thread] %logger{10} [%file:%line] %msg%n");
		
		a.setContext(lc);

		Map.Entry me = null;
		Iterator<?> i = m_loggers.entrySet().iterator();
		while (i.hasNext()) {
			me = (Map.Entry<String,String>) i.next();
			String loggerName = (String) me.getKey();
			String loggerClass = (String) me.getValue();
			Logger logger = (Logger) LoggerFactory.getLogger(loggerClass);
			TimeStampedFileAppender<ILoggingEvent> appender = null;
			appender = (TimeStampedFileAppender<ILoggingEvent>) logger.getAppender(loggerName);
			if (appender == null) {
				s_logger.warn("No appender was configured for {}", loggerName);
			} else {
				appender = (TimeStampedFileAppender<ILoggingEvent>) logger.getAppender(loggerName);
				m_appenders.put(loggerName, appender);
				s_logger.debug("Configured {}", loggerName);
			}
		}
		m_startTime = new Date();
		m_initialized = true;
		s_logger.debug("Logging has been initialized");
	}
	
	String getTimeStampedLogPath() {
		if (!m_initialized) {
			s_logger.error("*** getTimeStampedLogPath(): Not initialized ***");
		}
		return m_timeStampedLogPath;
	}
	
	/**
	 * Forces a timestamp based on start time and the current time
	 */
	public void setStopTime() {
		if (!m_initialized) {
			s_logger.error("*** setStopTime(): Not initialized ***");
		}
		if (m_startTime == null) {
			s_logger.warn("*** Test run log group not started"); // TODO: Figure out what to do here. Does it matter?
		}
		
		m_stopTime = new Date();
		setTimeStamp();
	}
	
	public TimeStampedFileAppender<?> getAppender(String appenderName) {
		return m_appenders.get(appenderName);
	}
	
	public void setAppender(String name, TimeStampedFileAppender<?> appender) {
		m_appenders.put(name, appender);
	}
	
	/**
	 * Creates the path names of the timestamped copy of each configured log
	 * 
	 */
	private void setTimeStamp() {
		if (!m_initialized) {
			s_logger.error("*** setTimeStamp(): Not initialized ***");
		}
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
				startCal.get(Calendar.YEAR), startCal.get(Calendar.MONTH) + 1, startCal.get(Calendar.DAY_OF_MONTH),
				startCal.get(Calendar.HOUR_OF_DAY), startCal.get(Calendar.MINUTE), startCal.get(Calendar.SECOND));
		
		// Loop on appenders
		Map.Entry me = null;
		Iterator<?> i = m_appenders.entrySet().iterator();
		while (i.hasNext()) {
			me = (Map.Entry<String,String>) i.next();
			String logName = (String) me.getKey();
			TimeStampedFileAppender<?> a = (TimeStampedFileAppender<?>) me.getValue();
			
			// Get separators straight		
			s_logger.debug("{} file path: {}", logName, a.getFile());
			File testFile = new File(a.getFile()); // Normalize by instantiating a File
			s_logger.debug("System canonical path: " + testFile.getPath());
			String currPath = testFile.getPath();
			// Check whether we're in a situation where separators are different than logger config (/)
			if (testFile.getAbsolutePath().lastIndexOf("/") < 0) {
				// Windows
				currPath = currPath.replaceAll("\\\\", "/");
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

	public boolean appendersConfigOk() {
		boolean rv = false;
		LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();

		Map<String, Appender<ILoggingEvent>> appendersMap = new HashMap<>();
		for (Logger logger : loggerContext.getLoggerList()) {

			Iterator<Appender<ILoggingEvent>> appenderIterator = logger.iteratorForAppenders();
			while (appenderIterator.hasNext()) {
				Appender<ILoggingEvent> appender = appenderIterator.next();
				if (!m_appenders.containsKey(appender.getName())) {
					s_logger.warn("No appender found for {}", appender.getName());
				} else {
					appendersMap.put(appender.getName(), (Appender<ILoggingEvent>) m_appenders.get(appender.getName()));
				}
			}
		}
		
		// Iterate through the configured logs to be sure we have appenders for CSV and APDU.

		return rv;
	}
}
