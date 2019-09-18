/**
 * 
 */
package gov.gsa.pivconformancegui;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import ch.qos.logback.core.joran.spi.JoranException;
import ch.qos.logback.core.util.StatusPrinter;

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
		Appender<ILoggingEvent> a = new GuiDebugAppender("%date %level [%thread] %logger{10} [%file:%line] %msg%n");
		a.setContext(ctx);
		
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
		bootStrapLogging();
		m_appenders = new HashMap<String, TimeStampedFileAppender<?>>();
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
				m_appenders.put(loggerName, appender);
				appender = (TimeStampedFileAppender<ILoggingEvent>) logger.getAppender(loggerName);
				appender.setImmediateFlush(true);
				appender.setAppend(false);
				if (appender.getName().equals("CONFORMANCELOG")) {
					File f = new File(appender.getFile());
					PrintStream p;
					try {
						p = new PrintStream(f);
						p.println("Date,Test Id,Description,Expected Result,Actual Result");
						p.close();
						s_logger.debug("Wrote header to {}", appender.getFile());
					} catch (Exception e) {
						s_logger.error("Can't initialize {}", appender.getFile());
					}
				}
				s_logger.debug("Initialized and configured {}", loggerName);
			}
		}
		m_startTime = new Date();
		m_initialized = true;
		TestExecutionController.getInstance().setTestRunLogController(this);
		s_logger.debug("Logging has been initialized");
	}
	
	/**
	 * Bootstraps the logging system with sane values
	 */
	static void bootStrapLogging() {
		LoggerContext ctx = (LoggerContext) LoggerFactory.getILoggerFactory();
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
		TestExecutionController tc = TestExecutionController.getInstance();
		tc.setLoggerContext(ctx);
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
		startTs =
			String.format("%04d%02d%02d_%02d%02d%02d", startCal.get(Calendar.YEAR),
			startCal.get(Calendar.MONTH) + 1, startCal.get(Calendar.DAY_OF_MONTH),
			startCal.get(Calendar.HOUR_OF_DAY), startCal.get(Calendar.MINUTE), startCal.get(Calendar.SECOND));
		stopTs = 
			String.format("%04d%02d%02d_%02d%02d%02d", endCal.get(Calendar.YEAR),
			endCal.get(Calendar.MONTH) + 1, endCal.get(Calendar.DAY_OF_MONTH),
			endCal.get(Calendar.HOUR_OF_DAY), endCal.get(Calendar.MINUTE), endCal.get(Calendar.SECOND));

		// Loop on appenders
		Entry<String, TimeStampedFileAppender<ILoggingEvent>> me = null;
		Iterator<?> i = m_appenders.entrySet().iterator();
		while (i.hasNext()) {
			me = (Map.Entry<String, TimeStampedFileAppender<ILoggingEvent>>) i.next();
			String logName = me.getKey();
			TimeStampedFileAppender<ILoggingEvent> appender = (TimeStampedFileAppender<ILoggingEvent>) me.getValue();
			Logger logger = (Logger) LoggerFactory.getLogger(m_loggers.get(me.getKey()));
			
			// Get separators straight
			s_logger.debug("{} file path: {}", logName, appender.getFile());
			File testFile = new File(appender.getFile()); // Normalize by instantiating a File
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
			appender.setTimeStampedLogPath(timeStampedLogPath);
			appender.stop();
			
			// Roll the log
			s_logger.debug("Copying log {} to: {}", logName, timeStampedLogPath);
			if (rollFile(currPath, timeStampedLogPath)) {
				s_logger.debug("Succesfully copied log to {}", timeStampedLogPath);
				File f = new File(".lastlog" + "-" + appender.getName().toLowerCase());
				try {
					PrintStream p = new PrintStream(f);
					p.println(timeStampedLogPath);
					p.close();
				} catch (IOException e) {
					s_logger.debug("Couldn't write last log name to .lastlog-{}: {}", appender.getName().toLowerCase(), e.getMessage());
				}
			} else {
				s_logger.error("Error copying {} to {}", currPath, timeStampedLogPath);
			}
			
			// Halt the appenders
			logger.detachAndStopAllAppenders();
		}
	}

	/**
	 * Copies the contents of oldPath to newPath and removes the existing
	 * 
	 * @param oldPath the original file
	 * @param newPath the new copy
	 * @return true if successful, false otherwise
	 */

	private boolean rollFile(String oldPath, String newPath) {
		boolean rv = false;
		s_logger.debug("Rolling {} to {}", oldPath, newPath);
		try {
			Files.copy(Paths.get(oldPath), Paths.get(newPath), StandardCopyOption.REPLACE_EXISTING,
					StandardCopyOption.COPY_ATTRIBUTES);
			try {
				Files.delete(Paths.get(oldPath));
				if (Files.exists(Paths.get(oldPath))) {
					s_logger.debug("Unable to remove {}", oldPath);
		    	}
			} catch (Exception e) {
				s_logger.debug("Unable to remove {}: ", oldPath, e.getMessage());
			}
			rv = true;
		} catch (IOException e) {
			s_logger.error("IOException '{}' while rolling files", e.getMessage());
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
	
	/**
	 * Gets the currently running directory
	 * @return the currently running directory
	 */
	
	public static String getCwd(String caller) {
		String rv = null;
		ProtectionDomain p;
		Class<?> cls;
		try {
			cls = Class.forName(caller);
			p = cls.getProtectionDomain();
			String tmp = pathFixup(p.getCodeSource().getLocation().getPath());
			String[] dirs = tmp.split("/");
			List<String> dirList = Arrays.asList(dirs);
			StringBuilder sb = new StringBuilder("");
			if (dirList.contains("bin") && dirList.contains("main")) {
				for (String d : dirList) {
					if (d.compareTo("bin") != 0) {
						if (d.length() > 0) {
							sb.append(d);
							sb.append("/");
						}
					} else {
						break;
					}
				}
			}
			rv = sb.toString();
		} catch (ClassNotFoundException e) {
			s_logger.error("Class {} not found", caller);
		}
		return rv;
	}
	/**
	 * Corrects the path separators for a path.
	 * 
	 * @param inPath
	 *            the path as read from a configuration file, etc.
	 * @return a path with the correct path separators for the local OS
	 */

	public static String pathFixup(String inPath) {
		String outPath = inPath;
		if (System.getProperty("os.name").toLowerCase().contains("windows")) {
			if (inPath.contains("/")) {
				outPath = inPath.replace("/", "\\");
			}
		} else if (inPath.contains("\\")) {
			outPath = inPath.replace("\\\\", "/");
		}

		return outPath;
	}
}
