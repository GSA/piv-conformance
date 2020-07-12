package gov.gsa.pivconformance.tlv;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CCTTlvLogger implements IBerTlvLogger {

	private Logger m_logger = null;

	public CCTTlvLogger(Class<?> clazz) {
		m_logger = LoggerFactory.getLogger(clazz.toString() + ".TLVParser");
	}

	@Override
	public boolean isDebugEnabled() {
		return m_logger != null && m_logger.isDebugEnabled();
	}

	@Override
	public void debug(String aFormat, Object... args) {
		if (m_logger == null)
			return;
		// m_logger.debug(aFormat, args);
	}
}
