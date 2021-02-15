package gov.gsa.pivconformance.cardlib.card.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.pivconformance.cardlib.card.client.APDUConstants;
import gov.gsa.pivconformance.cardlib.utils.ITransmitCounter;
import gov.gsa.pivconformance.cardlib.utils.PCSCWrapper;

/*
 * Workaround based on logic from the intarsys PCSC wrapper library, adapted to run
 * directly on top of javax.smartcardio.pcsc.
 */
public class ChainingAPDUTransmitter {
	
	private CardChannel m_channel = null;
    private static final Logger s_logger = LoggerFactory.getLogger(ChainingAPDUTransmitter.class);
    private static final Logger s_apduLogger = LoggerFactory.getLogger("gov.gsa.pivconformance.cardlib.apdu");
	private final ITransmitCounter m_counter;
	
	public ChainingAPDUTransmitter(CardChannel c) {
		m_channel = c;
		m_counter = PCSCWrapper.getInstance();
	}

	/**
	 * Formats the request with the appropriate LE byte
	 * @param request the request APDU
	 * @param correctLE LE byte
	 * @return the buffer returned from the smart card application
	 */
	protected RequestAPDUWrapper fixLengthExpected(RequestAPDUWrapper request, int correctLE) {
		int cla = request.getCla();
		int ins = request.getIns();
		int p1 = request.getP1();
		int p2 = request.getP2();
		byte[] data = request.getData();
		if (data == null) {
			return new RequestAPDUWrapper(cla, ins, p1, p2, correctLE);
		} else {
			return new RequestAPDUWrapper(cla, ins, p1, p2, data, correctLE);
		}
	}

	/**
	 *
	 * @param request the APDU request
	 * @return a response APDU wrapper containing the requested data
	 * @throws CardException if an error occurs
	 */
	ResponseAPDUWrapper nativeTransmit(RequestAPDUWrapper request) throws CardException, CardClientException {
		CommandAPDU cmd = new CommandAPDU(request.getBytes());
    	ResponseAPDU rsp = null;
    	try {
    		
			String apduTrace;
			// Mask PIN
	    	if (cmd.getINS() == APDUConstants.VERIFY) {
	    		byte[] maskedPin = cmd.getBytes();
	    		for (int i = 5, end = i + cmd.getNc(); i < end; i++) {
	    			maskedPin[i] = (byte) 0xAA;
	    		}
	    		apduTrace = String.format("Sending Command APDU %s", Hex.encodeHexString(maskedPin).replaceAll("..(?=.)", "$0 "));
	    	}
	    	else {
	    		apduTrace = String.format("Sending Command APDU %s", Hex.encodeHexString((cmd.getBytes())).replaceAll("..(?=.)", "$0 "));
	    	}
    		s_apduLogger.debug(apduTrace);
    		
    		m_counter.incrementTransmitCount();
			rsp = m_channel.transmit(cmd);
			s_apduLogger.debug(String.format("Received response %s", Hex.encodeHexString((rsp.getBytes())).replaceAll("..(?=.)", "$0 ")));
		} catch (CardException e) {
			s_logger.error("Caught CardException {} transmitting APDU.", e.getMessage(), e);
			throw e;
		}
		return new ResponseAPDUWrapper(rsp.getBytes());
	}
	
	protected ResponseAPDUWrapper basicTransmit(RequestAPDUWrapper request)
			throws CardClientException, CardException {
		RequestAPDUWrapper encodedRequest = encodeRequest(request);
		ResponseAPDUWrapper encodedResponse = nativeTransmit(
				encodedRequest);
		return decodeResponse(encodedResponse);
	}

	protected ResponseAPDUWrapper decodeResponse(ResponseAPDUWrapper response)
			throws CardException {
		return response;
	}

	protected RequestAPDUWrapper encodeRequest(RequestAPDUWrapper request)
			throws CardException {
		return request;
	}

	public ResponseAPDUWrapper transmit(RequestAPDUWrapper request) throws CardClientException, CardException {
		ResponseAPDUWrapper response = this.basicTransmit(request);
		if (response.getSw1() == 0x6C) {
			// wrong LengthExpected field: happens e.g. on ReinerSCT e-com in
			// combination with Starcos3.0 cards
			int le = response.getSw2();
			RequestAPDUWrapper fixedRequest = fixLengthExpected(request, le);
			response = this.basicTransmit(fixedRequest);
		}
		if (response.getSw1() == 0x61) {
			s_logger.debug("Using GET RESPONSE to retrieve large object");
			ByteArrayOutputStream dataBaos = new ByteArrayOutputStream();
			try {
				dataBaos.write(response.getData());
			} catch (IOException e) {
				s_logger.error("Failed to write data to byte array.", e);
				throw new CardClientException("Failed to write data to byte array.", e);
			}
			do {
				// "GET RESPONSE" command
				RequestAPDUWrapper fixedRequest = new RequestAPDUWrapper(0, 0xC0, 0, 0,
						response.getSw2());
				response = this.basicTransmit(fixedRequest);
				try {
					dataBaos.write(response.getData());
				} catch (IOException e) {
					s_logger.error("Caught exception appending to byte array", e);
					throw new CardClientException("Unable to append to byte array", e);
				}
			} while(response.getSw1() == 0x61);

			try {
				dataBaos.flush();
			} catch (IOException e) {
				s_logger.error("Unable to flush byte array output stream", e);
				throw new CardClientException("Unable to flush byte array output stream for GET RESPONSE handling.", e);
			}
			byte[] dataBytes = dataBaos.toByteArray();
			s_logger.debug("GET RESPONSE: final size: {}", dataBytes.length);
			ResponseAPDUWrapper fixedResponse = new ResponseAPDUWrapper(dataBytes, response.getSw1(), response.getSw2());
			s_logger.debug("Returning status {} following GET RESPONSE", String.format("%1$02X %2$02X", response.getSw1(), response.getSw2()));
			response = fixedResponse;
		}
		if (request.isChainedRequest() && request.getNextRequest() != null) {
			response = transmit(request.getNextRequest());
		}
		return response;
	}
}
