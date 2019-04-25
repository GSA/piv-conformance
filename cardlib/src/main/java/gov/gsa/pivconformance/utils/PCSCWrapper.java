package gov.gsa.pivconformance.utils;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PCSCWrapper {
    private static final Logger s_logger = LoggerFactory.getLogger(PCSCWrapper.class);
    private static final Logger s_apduLogger = LoggerFactory.getLogger("gov.gsa.pivconformance.apdu");
    private static PCSCWrapper INSTANCE = new PCSCWrapper();
    
    public Card connect(CardTerminal t) throws CardException {
    	s_logger.debug("Connecting to card in {} using the default protocol", t.getName());
    	return connect(t, "*");
    }
    
    public Card connect(CardTerminal t, String protocol) throws CardException {
    	s_logger.debug("Connecting to card in {} using protocol: \"{}\"", t.getName(), protocol);
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
    	ResponseAPDU rsp = null;
    	
    	if (cmd.getINS() == 0x20) {
    		// Pretty this up later
    		byte[] fakeVerify = cmd.getBytes();
    		for (int i = 5, end = i + cmd.getNc(); i < end; i++) {
    			fakeVerify[i] = (byte) 0xAA;
    		}
    		s_apduLogger.debug("Sending Command APDU: {}", Hex.encodeHexString(fakeVerify).replaceAll("..(?=.)", "$0 "));	
    	}
    	else {
    		s_apduLogger.debug("Sending Command APDU: {}", Hex.encodeHexString(cmd.getBytes()).replaceAll("..(?=.)", "$0 "));
    	}
    	
    	try {
			rsp = channel.transmit(cmd);
			s_apduLogger.debug("Received Response APDU: {}", Hex.encodeHexString(rsp.getBytes()).replaceAll("..(?=.)", "$0 "));
		} catch (CardException e) {
			s_logger.error("Caught CardException {} transmitting APDU.", e.getMessage(), e);
			throw e;
		}
    	return rsp;
    }
    
    private PCSCWrapper() {
    	
    }
    
    public static PCSCWrapper getInstance() {
    	return INSTANCE;
    }
    
}
