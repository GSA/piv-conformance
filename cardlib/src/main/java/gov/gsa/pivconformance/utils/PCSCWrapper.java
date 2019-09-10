package gov.gsa.pivconformance.utils;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.pivconformance.card.client.CardClientException;
import gov.gsa.pivconformance.card.client.ChainingAPDUTransmitter;
import gov.gsa.pivconformance.card.client.RequestAPDUWrapper;
import gov.gsa.pivconformance.card.client.ResponseAPDUWrapper;

public class PCSCWrapper implements ITransmitCounter{
    private static final Logger s_logger = LoggerFactory.getLogger(PCSCWrapper.class);
    private static PCSCWrapper INSTANCE = new PCSCWrapper();
    
    private int m_connectCount = 0;
    private int m_transmitCount = 0;
    
    public Card connect(CardTerminal t) throws CardException {
    	s_logger.debug("Connecting to card in {} using the default protocol", t.getName());
    	return connect(t, "*");
    }
    
    public Card connect(CardTerminal t, String protocol) throws CardException {
    	s_logger.debug("Connecting to card in {} using protocol: \"{}\"", t.getName(), protocol);
    	m_connectCount++;
    	Card rv = null;
    	try {
			rv = t.connect(protocol);
    	} catch(CardException e) {
    		s_logger.error("Caught CardException: {} while attempting to connect to card in {} using protocol \"{}\"",
    				e.getMessage(), t.getName(), protocol, e);
    		throw e;
    	}
    	s_logger.debug("Connected: {}", rv);
    	return rv;
    	
    }
    
    public ResponseAPDU transmit(CardChannel channel, CommandAPDU cmd) throws CardException {
    	s_logger.debug("transmit() wrapper called");
    	m_transmitCount++;
    	/*
    	ResponseAPDU rsp = null;
    	s_apduLogger.info("Sending Command APDU: {}", Hex.encodeHexString(cmd.getBytes()).replaceAll("..(?=.)", "$0 "));
    	try {
			rsp = channel.transmit(cmd);
			s_apduLogger.debug("Received Response APDU: {}", Hex.encodeHexString(rsp.getBytes()).replaceAll("..(?=.)", "$0 "));
		} catch (CardException e) {
			s_logger.error("Caught CardException {} transmitting APDU.", e.getMessage(), e);
			throw e;
		}
    	return rsp;
    	*/
    	ChainingAPDUTransmitter ct = new ChainingAPDUTransmitter(channel);
    	RequestAPDUWrapper req = new RequestAPDUWrapper(cmd.getBytes());
    	ResponseAPDUWrapper rsp = null;
		try {
			rsp = ct.transmit(req);
		} catch (CardClientException e) {
			s_logger.error("Failed to receive response APDU", e);
			return null;
		}
    	return new ResponseAPDU(rsp.getBytes());
    }
    
    private PCSCWrapper() {
    	
    }
    
    public static PCSCWrapper getInstance() {
    	return INSTANCE;
    }

	public int getTransmitCount() {
		return m_transmitCount;
	}

	public int getConnectCount() {
		return m_connectCount;
	}
	
	public void resetCounters() {
		m_connectCount = 0;
		m_transmitCount = 0;
	}
	
	@Override
	public void incrementTransmitCount() {
		m_transmitCount++;
	}

}
