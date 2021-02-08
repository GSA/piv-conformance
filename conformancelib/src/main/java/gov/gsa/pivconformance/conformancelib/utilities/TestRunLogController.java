/**
 * 
 */
package gov.gsa.pivconformance.conformancelib.utilities;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import ch.qos.logback.core.joran.spi.JoranException;
import ch.qos.logback.core.util.StatusPrinter;
import gov.gsa.pivconformance.cardlib.card.client.APDUConstants;
import gov.gsa.pivconformance.cardlib.card.client.ArtifactWriter;
import gov.gsa.pivconformance.cardlib.card.client.CardHolderUniqueIdentifier;
import gov.gsa.pivconformance.cardlib.card.client.PIVDataObject;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.ProtectionDomain;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

/**
 * Singleton class that consolidates the appenders into a single disposable group
 *
 */
public class TestRunLogController {

	private static final org.slf4j.Logger s_logger = LoggerFactory.getLogger(TestRunLogController.class);
	private static final TestRunLogController INSTANCE = new TestRunLogController();

	/*
	 * Note that these names MUST match the user_log_config.xml appender names.
	 * start time, end time, log file path name. It instantiates and destroys
	 * appenders as a group, but is ephemeral, so we can re-create a group each run.
	 */
	static final HashMap<String, String> m_loggers = new HashMap<String, String>() {
		static final long serialVersionUID = 1L;

		{
			put("DEBUG", "gov.gsa");
			put("CONFORMANCELOG", "gov.gsa.pivconformance.conformancelib.testResult");
			put("TESTLOG", "gov.gsa.pivconformance.conformancelib.testProgress");
			put("APDULOG", "gov.gsa.pivconformance.cardlib");

			/* Container logs */
			put("BIOMETRICINFORMATIONTEMPLATESGROUPTEMPLATE", "BiometricInformationTemplatesGroupTemplate");
			put("CARDCAPABILITYCONTAINER", "CardCapabilityContainer");
			put("CARDHOLDERUNIQUEIDENTIFIER", "CardHolderUniqueIdentifier");
			put("CARDHOLDERFINGERPRINTS", "CardholderFingerprints");
			put("CARDHOLDERFACIALIMAGE", "CardholderFacialImage");
			put("CARDHOLDERIRISIMAGES", "CardholderIrisImages");
			put("DISCOVERYOBJECT", "DiscoveryObject");
			put("KEYHISTORYOBJECT", "KeyHistoryObject");
			put("PAIRINGCODEREFERENCEDATACONTAINER", "PairingCodeReferenceDataContainer");
			put("PRINTEDINFORMATION", "PrintedInformation");
			put("SECUREMESSAGINGCERTIFICATESIGNER", "SecureMessagingCertificateSigner");
			put("SECURITYOBJECT", "SecurityObject");
			put("X509CERTIFICATEFORPIVAUTHENTICATION", "X509CertificateForPIVAuthentication");
			put("X509CERTIFICATEFORCARDAUTHENTICATION", "X509CertificateForCardAuthentication");
			put("X509CERTIFICATEFORDIGITALSIGNATURE", "X509CertificateForDigitalSignature");
			put("X509CERTIFICATEFORKEYMANAGEMENT", "X509CertificateForKeyManagement");
			put("SECUREMESSAGINGCERTIFICATESIGNER", "SecureMessagingCertificateSigner");
		}
	};

	private HashMap<String, TimeStampedFileAppender<?>> m_appenders = null;
	private HashMap<String, String> m_filenames = null;
	private LoggerContext m_ctx = null;
	private boolean m_initialized = false;
	private final String m_timeStampedLogPath = null;
	private String m_timeStamp = null;
	private String m_fascn = null;
	private String m_guid = null;

	public static TestRunLogController getInstance() {
		return INSTANCE;
	}

	public void initialize() {
		if (m_ctx != null)
			initialize(m_ctx);
	}

	/**
	 * Initializes a new TestRunLogController. One must be created per instance of CCT. ]
	 *
	 * @param ctx the logger context - one per application.
	 */
	@SuppressWarnings("unchecked")
	public void initialize(LoggerContext ctx) {
		if (m_appenders == null) {
			m_appenders = new HashMap<String, TimeStampedFileAppender<?>>();
			m_filenames = new HashMap<String, String>();
			m_guid = null;
			m_fascn = null;
			Map.Entry<String, String> me = null;
			Iterator<?> i = m_loggers.entrySet().iterator();

			Date startTime = new Date();

			while (i.hasNext()) {
				me = (Map.Entry<String, String>) i.next();
				String loggerName = me.getKey();
				String loggerClass = me.getValue();

				Logger logger = (Logger) LoggerFactory.getLogger(loggerClass);
				TimeStampedFileAppender<ILoggingEvent> appender = null;

				if ((appender = (TimeStampedFileAppender<ILoggingEvent>) logger.getAppender(loggerName)) != null) {
					m_filenames.put(loggerName, appender.getFile());
					m_appenders.put(loggerName, appender);
					try {
						appender.getOutputStream().flush();
					} catch (Exception e) {
						e.printStackTrace(); // TODO: clean this up
					}

					appender.setAppend(false);
					appender.setStartTime(startTime);
					appender.setStopTime(startTime); // Gets overwritten

					// For the CONFORMANCE CSV log, initialize the output file writing the header row
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
				} else {
					s_logger.warn("No appender was configured for {}", loggerName);
				}
			}

			m_initialized = true;
			s_logger.debug("Logging has been initialized");
		}
	}

	/**
	 * Bootstraps the logging system with sane values
	 * @param logConfigFile log config File
	 */
	public void bootStrapLogging(File logConfigFile) {
		m_ctx = (LoggerContext) LoggerFactory.getILoggerFactory();
		try {
			if (logConfigFile.exists() && logConfigFile.canRead()) {
				JoranConfigurator configurator = new JoranConfigurator();
				// overriding the log directory property programmatically
				m_ctx.putProperty("LOG_DIR", "logs");
				configurator.setContext(m_ctx);
				configurator.doConfigure(logConfigFile.getCanonicalPath());
			}
		} catch (JoranException e) {
			// handled by status printer
		} catch (IOException e) {
			System.err.println("Unable to resolve logging config to a readable file");
			e.printStackTrace();
		} catch (Exception e) {
			System.err.println("Exception opening user log config file: " + e.getMessage());
		}
		StatusPrinter.printIfErrorsOccured(m_ctx);
		TestRunLogController trlc = getInstance();
		trlc.initialize(m_ctx);
	}

	/**
	 * Gets LoggerContext of the logging subsystem
	 *
	 * @return LoggerContext of the logging subsystem
	 */

	public LoggerContext getLoggerContext() {
		if (!m_initialized) {
			s_logger.error("*** getLoggerContext(): Not initialized ***");
		}
		return m_ctx;
	}

	/**
	 * Gets the time-stamp
	 *
	 * @return string containing the time stamp
	 */

	public String getTimeStamp() {
		if (!m_initialized) {
			s_logger.error("*** getTimeStamp(): Not initialized ***");
		}
		return m_timeStamp;
	}

	/**
	 * Gets the appender object associated with a friendly name
	 * @param appenderName
	 * @return appender object
	 */
	/**
	 * Gets the time-stamped log path created by the stop() method.
	 *
	 * @return string containing the full path to the requested time-stamped file
	 */

	public String getTimeStampedLogPath() {
		if (!m_initialized) {
			s_logger.error("*** getTimeStampedLogPath(): Not initialized ***");
		}
		return m_timeStampedLogPath;
	}


	/**
	 * Gets the appender object associated with a friendly name
	 *
	 * @param appenderName appender name
	 * @return appender object appender for name
	 */

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
	 * Creates an appender's log path consisting of a start and stop timestamp
	 *
	 * @param appender the appender
	 * @returns the log path for the appender
	 */

	private String makeTimeStampedLogPath(TimeStampedFileAppender<ILoggingEvent> appender, Date stopTime) {

		String startTs = null;
		String stopTs = null;

		appender.setStopTime(stopTime);

		GregorianCalendar startCal = (GregorianCalendar) Calendar.getInstance();
		startCal.setTime(appender.getStartTime());
		GregorianCalendar endCal = (GregorianCalendar) Calendar.getInstance();
		endCal.setTime(appender.getStopTime());

		String identifier = null;

		// It is only a guess as to whether this is a PIV-I or not. We just need one of the two
		// for our file name.
		if (getGuid() != null && getFascn() != null && getFascn().startsWith("99999999999999")) {
			// Use the GUID
			identifier = getGuid();
		} else if (getFascn() != null) {
			// Use the FASC-N
			identifier = getFascn();
		}

		startTs =
				String.format("%s_%04d%02d%02d_%02d%02d%02d", identifier, startCal.get(Calendar.YEAR),
						startCal.get(Calendar.MONTH) + 1, startCal.get(Calendar.DAY_OF_MONTH),
						startCal.get(Calendar.HOUR_OF_DAY), startCal.get(Calendar.MINUTE), startCal.get(Calendar.SECOND));
		stopTs =
				String.format("%04d%02d%02d_%02d%02d%02d", endCal.get(Calendar.YEAR),
						endCal.get(Calendar.MONTH) + 1, endCal.get(Calendar.DAY_OF_MONTH),
						endCal.get(Calendar.HOUR_OF_DAY), endCal.get(Calendar.MINUTE), endCal.get(Calendar.SECOND));

		// Get separators straight
		s_logger.debug("{} file path: {}", appender.getName(), appender.getFile());
		File testFile = new File(appender.getFile()); // Normalize by instantiating a File (do we need to do this?)
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

		m_timeStamp = startTs + "-" + stopTs;
		String baseName = (m_timeStamp + "-" + logFileName);
		String timeStampedLogPath = dirName + "/" + baseName;

		return timeStampedLogPath;
	}

	/**
	 * Captures the identifiers from the currently executing test case.
	 * This is a convenience method used to create identifying timestamps.
	 */
	public void captureIdentifiers() {
		PIVDataObject o = AtomHelper.getDataObject(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
		if (o.decode()) {
			byte[] fascn = ((CardHolderUniqueIdentifier)o).getfASCN();
			if (fascn != null) {
				String cookedFascn = CardHolderUniqueIdentifier.cook(fascn);
				setFascn(cookedFascn);
			}
			byte[] guid = ((CardHolderUniqueIdentifier) o).getgUID();
			if (guid != null) {
				String cookedGuid = CardHolderUniqueIdentifier.guid2str(guid);
				setGuid(cookedGuid);
			}
		} else {
			s_logger.error("Couldn't decode CHUID");
		}
	}

	public void setFascn(String fascn) {
		m_fascn = fascn;
	}
	public String getFascn() { return m_fascn; }
	public void setGuid(String guid) {
		m_guid = guid;
	}
	public String getGuid() { return m_guid; }
	
	@SuppressWarnings("unchecked")
	public void setStartTimes() {
		if (!m_initialized) {
			s_logger.error("*** setTimeStamp(): Not initialized ***");
		}
		
		Date startTime = new Date();
		
		// Loop on appenders
		Entry<String, TimeStampedFileAppender<ILoggingEvent>> me = null;
		Iterator<?> i = m_appenders.entrySet().iterator();
		while (i.hasNext()) {
			me = (Map.Entry<String, TimeStampedFileAppender<ILoggingEvent>>) i.next();
			TimeStampedFileAppender<ILoggingEvent> appender = me.getValue();
			appender.setStartTime(startTime);
		}	
	}
	
	@SuppressWarnings("unchecked")
	/**
	 * Synchronizes the time stamps of all of the logs
	 */
	public void setTimeStamps() {
		
		if (!m_initialized) {
			s_logger.error("*** setTimeStamp(): Not initialized ***");
		}
		
		Date stopTime = new Date();

		// Loop on appenders
		Entry<String, TimeStampedFileAppender<ILoggingEvent>> me = null;
		Iterator<?> i = m_appenders.entrySet().iterator();
		while (i.hasNext()) {
			me = (Map.Entry<String, TimeStampedFileAppender<ILoggingEvent>>) i.next();
			String logName = me.getKey();
			Logger logger = (Logger) LoggerFactory.getLogger(m_loggers.get(me.getKey()));
			TimeStampedFileAppender<ILoggingEvent> appender = me.getValue();
			setTimeStamp(logger, appender, logName, stopTime);
		}
	}

	/**
	 * Creates the path names of the timestamped copy of each configured log
	 * @param logger the logger
	 * @param appender the appender
	 * @param logName the logger's friendly name
	 * @param stopTime stop time
	 * 
	 */
	public void setTimeStamp(Logger logger, TimeStampedFileAppender<ILoggingEvent> appender, String logName, Date stopTime) {

		String timeStampedLogPath = makeTimeStampedLogPath(appender, stopTime);
		String currentLogPath = new File(appender.getFile()).getPath();
		
		// Roll the log
		appender.stop();
		s_logger.debug("Copying log {} to: {}", logName, timeStampedLogPath);
		if (rollFile(currentLogPath, timeStampedLogPath)) {
			s_logger.debug("Succesfully copied log to {}", timeStampedLogPath);

			// Reset the name to the "base" file name minus a timestamp
			appender.setFile(m_filenames.get(appender.getName()));
			
			if (appender.getName().equals("CONFORMANCELOG")) {
				File f = new File(".lastlog" + "-" + appender.getName().toLowerCase());
				try {
					PrintStream p = new PrintStream(f);
					p.println(timeStampedLogPath);
					p.close();
				} catch (IOException e) {
					s_logger.debug("Couldn't write last log name to .lastlog-{}: {}", appender.getName().toLowerCase(), e.getMessage());
				}
			}
		} else {
			s_logger.error("Error copying {} to {}", currentLogPath, timeStampedLogPath);
		}
		appender.start();
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
					s_logger.warn("Unable to remove {}", oldPath);
		    	}
			} catch (Exception e) {
				s_logger.error("Unable to remove {}: {}", oldPath, e.getMessage());
			}
			rv = true;
		} catch (NoSuchFileException e) {
			s_logger.error("NoSuchFileException '{}' while rolling files", e.getMessage());

		} catch (IOException e) {
			s_logger.error("IOException '{}' while rolling files", e.getMessage());
		}
		return rv;
	}
	
	/**
	 * Removes the default log file names
	 * 
	 */
	
	@SuppressWarnings("unchecked")
	public void cleanup() {
		Map.Entry<String, String> me = null;
		Iterator<?> i = m_loggers.entrySet().iterator();
		ArtifactWriter.prependNames(m_timeStamp);
		ArtifactWriter.clean();
		while (i.hasNext()) {
			me = (Map.Entry<String, String>) i.next();
			String loggerName = me.getKey();
			String loggerClass = me.getValue();
	
			Logger logger = (Logger) LoggerFactory.getLogger(loggerClass);
			TimeStampedFileAppender<ILoggingEvent> appender = null;
	
			try {
				appender = (TimeStampedFileAppender<ILoggingEvent>) logger.getAppender(loggerName);
				if (appender != null) {
					File f = new File(appender.getFile());
					f.delete();
				}
			} catch (Exception e) {
				s_logger.warn("Can't delete {}: {}", appender.getFile(), e.getMessage());
			}
		}
	}
	
	/**
	 * Indicates the the configured appenders are set up and named properly
	 * 
	 * @return true if required appenders are configured, false otherwise
	 */

	@SuppressWarnings("unchecked")
	public boolean appendersConfigured() {

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
	 * Gets the currently running directory based on input
	 * @param caller class to obtain directory for
	 * @return the currently running directory w.r.t input class
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
			String[] dirList = dirs;
			StringBuilder sb = new StringBuilder();
			if (tmp.matches("/bin/main")) {
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
