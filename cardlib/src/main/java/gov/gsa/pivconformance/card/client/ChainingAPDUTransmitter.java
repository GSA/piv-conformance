package gov.gsa.pivconformance.card.client;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ChainingAPDUTransmitter {
	
	private CardChannel m_channel = null;
    private static final Logger s_logger = LoggerFactory.getLogger(ChainingAPDUTransmitter.class);
    private static final Logger s_apduLogger = LoggerFactory.getLogger("gov.gsa.pivconformance.apdu");
	
	public ChainingAPDUTransmitter(CardChannel c) {
		m_channel = c;
	}
	
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
	
	ResponseAPDUWrapper nativeTransmit(RequestAPDUWrapper request) throws CardException, CardClientException {
		CommandAPDU cmd = new CommandAPDU(request.getBytes());
    	s_apduLogger.info("Sending Command APDU: {}", Hex.encodeHexString(cmd.getBytes()).replaceAll("..(?=.)", "$0 "));
    	ResponseAPDU rsp = null;
    	try {
			rsp = m_channel.transmit(cmd);
			s_apduLogger.info("Received Response APDU: {}", Hex.encodeHexString(rsp.getBytes()).replaceAll("..(?=.)", "$0 "));
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
			// "GET RESPONSE" command
			RequestAPDUWrapper fixedRequest = new RequestAPDUWrapper(0, 0xC0, 0, 0,
					response.getSw2());
			response = this.basicTransmit(fixedRequest);
		}
		if (request.isChainedRequest() && request.getNextRequest() != null) {
			response = transmit(request.getNextRequest());
		}
		return response;
	}
}
