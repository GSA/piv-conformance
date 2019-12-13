/**
 * 
 */
package gov.gsa.pivconformancegui;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.qos.logback.core.FileAppender;

/**
 * This appender allows the user to have fine-tuned control over the capture
 * of events into log files whose names are start/stop timestamps.
 */
public class TimeStampedFileAppender<E> extends FileAppender<E> {
	private static final Logger s_logger = LoggerFactory.getLogger(TimeStampedFileAppender.class);
	private String m_timeStampedLogPath = "not initialized";
	private Date m_startTime;
	private Date m_stopTime;

	@Override
	public void start() {
		super.start();
		m_startTime = new Date();
	}

	@Override
	public void stop() {
		super.stop();
		m_stopTime = new Date();
	}

	@Override
	public void setFile(String file) {
		super.setFile(file);
	}

	@Override
	public String getFile() {
		return super.getFile();
	}

	@Override
	public void subAppend(E event) {
		super.subAppend(event);
	}
	
	public Date getStartTime() {
		return m_startTime;
	}
	
	public Date getStopTime() {
		return m_stopTime;
	}
	
	public String getTimeStampedLogPath() {
		return m_timeStampedLogPath;
	}
	
	public void setTimeStampedLogPath(String logPath) {
		m_timeStampedLogPath = logPath;
	}
}
