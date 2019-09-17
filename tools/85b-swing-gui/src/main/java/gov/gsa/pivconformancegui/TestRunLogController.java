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

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import ch.qos.logback.core.util.FileSize;

/**
 * Class that consolidates the appenders into a single disposable group
 *
 */
public class TestRunLogController {
	private static final org.slf4j.Logger s_logger = LoggerFactory.getLogger(TestRunLogController.class);
	/*
	 * Note that these names MUST match the user_log_config.xml appender names.
	 * start time, end time, log file path name. It instantiates and destroys
	 * appenders as a group, but is ephemeral, so we can re-create a group each run.
	 */
	static final HashMap<String, String> m_loggers = new HashMap<String, String>() {
		static final long serialVersionUID = 1L;
		{
			put("TESTLOG", "gov.gsa.pivconformance.testProgress");
			put("CONFORMANCELOG", "gov.gsa.pivconformance.testResults");
			put("APDULOG", "gov.gsa.pivconformance.apdu");
		}
	};

	private HashMap<String, TimeStampedFileAppender<?>> m_appenders = null;
	private boolean m_initialized = false;
	private String m_timeStampedLogPath = null;
	private Date m_startTime = null;
	private Date m_stopTime = null;

	/*
	 * Constructor
	 */
	public TestRunLogController() {
		LoggerContext ctx = TestExecutionController.getInstance().getLoggerContext();
		this.initialize(ctx);
		if (this.appendersConfigured()) {
			s_logger.error("Logger configuration error");
		}
	}

	/**
	 * Initializes a new TestRunLogController. One must be created per test run. ]
	 * 
	 * @param ctx the logger context - one per application.
	 */
	@SuppressWarnings("unchecked")
	void initialize(LoggerContext ctx) {
		m_appenders = new HashMap<String, TimeStampedFileAppender<?>>();

		// Bootstrap the Logging

		Appender<ILoggingEvent> a = new GuiDebugAppender("%date %level [%thread] %logger{10} [%file:%line] %msg%n");
		LoggerContext lc = (LoggerContext) LoggerFactory.getILoggerFactory();
		a.setContext(ctx);

		Map.Entry<String, String> me = null;
		Iterator<?> i = m_loggers.entrySet().iterator();
		while (i.hasNext()) {
			me = (Map.Entry<String, String>) i.next();
			String loggerName = me.getKey();
			String loggerClass = me.getValue();
			Logger logger = (Logger) LoggerFactory.getLogger(loggerClass);
			TimeStampedFileAppender<ILoggingEvent> appender = null;
			appender = (TimeStampedFileAppender<ILoggingEvent>) logger.getAppender(loggerName);
			if (appender == null) {
				s_logger.warn("No appender was configured for {}", loggerName);
			} else {
				appender = (TimeStampedFileAppender<ILoggingEvent>) logger.getAppender(loggerName);
				appender.setImmediateFlush(true);
				m_appenders.put(loggerName, appender);
				s_logger.debug("Configured {}", loggerName);
			}
		}
		m_startTime = new Date();
		m_initialized = true;
		s_logger.debug("Logging has been initialized");
	}

	/**
	 * Gets the time-stamped log path created by the stop() method.
	 * 
	 * @return string containing the full path to the requested time-stamped file
	 */

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

	/**
	 * Sets an appender for the specified logger
	 * 
	 * @param name     the name of the logger
	 * @param appender a TimeStampedFileAppender
	 */
	public void setAppender(String name, TimeStampedFileAppender<?> appender) {
		m_appenders.put(name, appender);
	}

	/**
	 * Creates the path names of the timestamped copy of each configured log
	 * 
	 */
	@SuppressWarnings("unchecked")
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
		startTs = String.format("%04d%02d%02d_%02d%02d%02d", startCal.get(Calendar.YEAR),
				startCal.get(Calendar.MONTH) + 1, startCal.get(Calendar.DAY_OF_MONTH),
				startCal.get(Calendar.HOUR_OF_DAY), startCal.get(Calendar.MINUTE), startCal.get(Calendar.SECOND));
		stopTs = String.format("%04d%02d%02d_%02d%02d%02d", startCal.get(Calendar.YEAR),
				startCal.get(Calendar.MONTH) + 1, startCal.get(Calendar.DAY_OF_MONTH),
				startCal.get(Calendar.HOUR_OF_DAY), startCal.get(Calendar.MINUTE), startCal.get(Calendar.SECOND));

		// Loop on appenders
		Entry<String, TimeStampedFileAppender<ILoggingEvent>> me = null;
		Iterator<?> i = m_appenders.entrySet().iterator();
		while (i.hasNext()) {
			me = (Map.Entry<String, TimeStampedFileAppender<ILoggingEvent>>) i.next();
			String logName = me.getKey();
			TimeStampedFileAppender<ILoggingEvent> a = (TimeStampedFileAppender<ILoggingEvent>) me.getValue();

			// Get separators straight
			s_logger.debug("{} file path: {}", logName, a.getFile());
			File testFile = new File(a.getFile()); // Normalize by instantiating a File
			s_logger.debug("System canonical path: " + testFile.getPath());
			String currPath = testFile.getPath();
			// Check whether we're in a situation where separators are different than logger
			// config (/)
			if (testFile.getAbsolutePath().lastIndexOf("/") < 0) {
				// Windows
				currPath = currPath.replaceAll("\\\\", "/");
			}

			// Synchronize timestamp portion of path
			String dirName = null;
			if (currPath.lastIndexOf("/") > -1)
				dirName = currPath.substring(0, currPath.lastIndexOf("/"));
			else
				dirName = currPath;

			String logFileName = null;
			if (currPath.lastIndexOf("/") > -1)
				logFileName = currPath.substring(currPath.lastIndexOf("/") + 1);
			else
				logFileName = currPath;
			
			String baseName = (startTs + "-" + stopTs + "-" + logFileName);
			String timeStampedLogPath = dirName + "/" + baseName;
			a.setTimeStampedLogPath(timeStampedLogPath);
			s_logger.debug("Setting {} to: {}", logName, timeStampedLogPath);

			try {
				a.stop();
				a.setBufferSize(new FileSize(0));
				a.openFile(a.getFile());
				a.start();
				a.stop();
				a.setBufferSize(new FileSize(8192));
				if (copyFile(currPath, timeStampedLogPath)) {
					if (!new File(currPath).delete()) {
						s_logger.warn("Couldn't delete {}", currPath);
					}
					s_logger.debug("Succesfully extracted {}", timeStampedLogPath);
				} else {
					s_logger.error("Error extracting {}", timeStampedLogPath);
				}
				// Make the copy
				a.setImmediateFlush(true);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				s_logger.error("Error copying {}", a.getFile());
			}
		}
	}

	/**
	 * Copies the contents of oldPath to newPath
	 * 
	 * @param oldPath the original file
	 * @param newPath the new copy
	 * @return true if successful, false otherwise
	 */

	private boolean copyFile(String oldPath, String newPath) {
		boolean rv = false;
		s_logger.debug("Copying {} to {}", oldPath, newPath);
		try {
			Files.copy(Paths.get(oldPath), Paths.get(newPath), StandardCopyOption.REPLACE_EXISTING,
					StandardCopyOption.COPY_ATTRIBUTES);
		} catch (IOException e) {
			s_logger.error("IOException: " + e.getMessage());
		}
		return rv;
	}

	/**
	 * Indicates the the configured appenders are set up and named properly
	 * 
	 * @return true if required appenders are configured, false otherwise
	 */

	@SuppressWarnings("unchecked")
	public boolean appendersConfigured() {
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
					appendersMap.put(appender.getName(), (Appender) m_appenders.get(appender.getName()));
				}
			}
		}

		// Iterate through the configured appender to be sure we have appenders
		// for CSV and APDU.

		Entry<String, TimeStampedFileAppender<ILoggingEvent>> me = null;
		Iterator<?> i = m_appenders.entrySet().iterator();
		int x = 0;
		int y = m_appenders.size();
		while (i.hasNext()) {
			me = (Map.Entry<String, TimeStampedFileAppender<ILoggingEvent>>) i.next();
			String logName = me.getKey();
			if (logName.equalsIgnoreCase(logName))
				x++;
		}
		return (x == y);
	}
}
