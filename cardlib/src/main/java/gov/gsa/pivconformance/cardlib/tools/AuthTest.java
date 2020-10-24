package gov.gsa.pivconformance.cardlib.tools;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.pivconformance.cardlib.utils.PCSCUtils;
import gov.gsa.pivconformance.cardlib.utils.PCSCWrapper;

public class AuthTest {
	
	
	private static final Logger s_logger = LoggerFactory.getLogger(AuthTest.class);

	static {
		PCSCUtils.ConfigureUserProperties();
	}
	
	public static void main(String[] args) {
		s_logger.info("testing card auth");
		String readerName = PCSCUtils.GetFirstReaderWithCardPresent();
		if(readerName == null) {
			s_logger.error("No reader had a card. Insert a card into a reader and try again");
			System.exit(1);
		}
		CardTerminal reader = PCSCUtils.TerminalForReaderName(readerName);
		s_logger.info("Using {}", reader.getName());
		Card piv = null;
		try {
			PCSCWrapper pcsc = PCSCWrapper.getInstance();
			piv = pcsc.connect(reader);
		} catch (CardException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		s_logger.info("Connected: {}", piv);
		byte[] select = {(byte)0x00, (byte)0xa4, (byte)0x04, (byte) 0x00, (byte) 0x0B,
				(byte)0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00
		};
		byte[] apdu = {(byte)0x00, (byte)0x20, (byte)0x00, (byte)0x80, (byte)0x00 };
		CardChannel c;
		try {
			c = piv.openLogicalChannel();
		} catch (CardException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			c = piv.getBasicChannel();
		} //piv.getBasicChannel();
		CommandAPDU sel = new CommandAPDU(select);
		try {
			ResponseAPDU rspAPDU = c.transmit(sel);
			s_logger.info("Sent: {} Received: {}", Hex.encodeHexString(sel.getBytes()), Hex.encodeHexString(rspAPDU.getBytes()));
			ResponseAPDU rspAPDU2 = c.transmit(sel);
			s_logger.info("Sent: {} Received: {}", Hex.encodeHexString(sel.getBytes()), Hex.encodeHexString(rspAPDU2.getBytes()));
		} catch (CardException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		CommandAPDU cmd = new CommandAPDU(apdu);
		try {
			c = piv.getBasicChannel();
			ResponseAPDU rsp = c.transmit(cmd);
			s_logger.info("Sent: {} Received: {}", Hex.encodeHexString(cmd.getBytes()), Hex.encodeHexString(rsp.getBytes()));
		} catch (CardException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		s_logger.error("Done!");
		
	}

}
