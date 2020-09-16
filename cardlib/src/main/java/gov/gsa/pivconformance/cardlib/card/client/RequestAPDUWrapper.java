package gov.gsa.pivconformance.cardlib.card.client;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// derived from the intarsys ReqeuestAPDU class
public class RequestAPDUWrapper {
    private static final Logger s_logger = LoggerFactory.getLogger(RequestAPDUWrapper.class);

	/* command is not the last command of a chain */
	public static final byte CLA_CHAINING_FLAG = 0x10;

	public static final int LE_MAX = 0;
	public static final int LE_NONE = -1;

	private RequestAPDUWrapper nextRequest;

	private final int cla;
	private final int ins;
	private final int p1;
	private final int p2;
	private final byte[] data;
	private final byte[] bytes;
	private final int le;

	private boolean extendedApdu = false;

	/**
	 * Flag if this content should be hidden in debugging contexts
	 */
	private boolean sensitiveContent = false;

	private boolean chainedRequest = false;

	public RequestAPDUWrapper(byte[] bytes) {
		super();
		this.bytes = bytes;
		cla = 0;
		ins = 0;
		p1 = 0;
		p2 = 0;
		data = null;
		le = RequestAPDUWrapper.LE_NONE;
	}

	public RequestAPDUWrapper(int pCla, int pIns, int pP1, int pP2) {
		this(pCla, pIns, pP1, pP2, null, LE_NONE);
	}

	public RequestAPDUWrapper(int pCla, int pIns, int pP1, int pP2, byte[] pData) {
		this(pCla, pIns, pP1, pP2, pData, LE_NONE);
	}

	public RequestAPDUWrapper(int pCla, int pIns, int pP1, int pP2, byte[] pData,
			int pLe) {
		cla = pCla;
		ins = pIns;
		p1 = pP1;
		p2 = pP2;
		le = pLe;
		data = filterEmptyData(pData);
		bytes = null;
	}

	public RequestAPDUWrapper(int pCla, int pIns, int pP1, int pP2, int pLe) {
		this(pCla, pIns, pP1, pP2, null, pLe);
	}

	private byte[] filterEmptyData(byte[] pData) {
		if (pData == null || pData.length == 0) {
			return null;
		}
		return pData;
	}

	/**
	 * The byte sequence for the complete encoded request.
	 * 
	 * @return
	 */
	public byte[] getBytes() {
		if (bytes != null) {
			return bytes;
		}
		byte[] buffer = new byte[getLength()];

		buffer[0] = (byte) getCla();
		buffer[1] = (byte) getIns();
		buffer[2] = (byte) getP1();
		buffer[3] = (byte) getP2();
		int index = 4;
		boolean markExtended = true;
		if (data != null) {
			if (isExtendedApdu()) {
				buffer[index] = 0; // extended length
				buffer[index + 1] = (byte) ((data.length >> 8) & 0xFF);
				buffer[index + 2] = (byte) (data.length & 0xff);
				index = index + 3;
				markExtended = false;
			} else {
				buffer[index] = (byte) data.length; // data length
				index = index + 1;
			}
			System.arraycopy(data, 0, buffer, index, data.length);
			index = index + data.length;
		}
		if (le != LE_NONE) {
			if (isExtendedApdu()) {
				if (markExtended) {
					buffer[index] = 0; // extended length
					index = index + 1;
				}
				buffer[index] = (byte) ((le >> 8) & 0xFF);
				buffer[index + 1] = (byte) (le & 0xff);
			} else {
				buffer[index] = (byte) (le & 0xff);
			}
		}
		return buffer;
	}

	/**
	 * The class indicator.
	 * 
	 * @return
	 */
	public int getCla() {
		if (isChainedRequest()) {
			return cla | CLA_CHAINING_FLAG;
		}
		return cla;
	}

	/**
	 * The net data transproted by the APDU.
	 * 
	 * @return
	 */
	public byte[] getData() {
		return data;
	}

	/**
	 * The instruction indicator
	 * 
	 * @return
	 */
	public int getIns() {
		return ins;
	}

	/**
	 * The expected length
	 * 
	 * @return
	 */
	public int getLe() {
		return le;
	}

	/**
	 * The total encoded APDU length
	 * 
	 * @return
	 */
	public int getLength() {
		if (bytes != null) {
			return bytes.length;
		}
		int length = 4;
		int lcle_first = 0;
		int lcle_all = 1;
		if (isExtendedApdu()) // extended apdu
		{
			lcle_first = 1;
			lcle_all = 2;
		}
		if (data != null) // data present
		{
			length += data.length;
			length += lcle_first;
			lcle_first = 0;
			length += lcle_all;
		}
		if (le != LE_NONE) // le present
		{
			length += lcle_first;
			length += lcle_all;
		}
		return length;
	}

	public RequestAPDUWrapper getNextRequest() {
		return nextRequest;
	}

	/**
	 * The P1 byte
	 * 
	 * @return
	 */
	public int getP1() {
		return p1;
	}

	/**
	 * The P2 byte
	 * 
	 * @return
	 */
	public int getP2() {
		return p2;
	}

	/**
	 * The expected length of the received byte array.
	 * 
	 * @return
	 */
	public int getReceiveLength() {
		if (bytes != null) {
			return 507;
		}
		if (le == RequestAPDUWrapper.LE_NONE) {
			return 2;
		}
		if (le == RequestAPDUWrapper.LE_MAX) {
			if (isExtendedApdu()) {
				/*
				 * max value for TCOS 3.0
				 */
				return 507;
			}
			return 256 + 2;
		}
		return le + 2;
	}

	public void insertHeader(byte[] destination, int offset) {
		destination[offset + 0] = (byte) getCla();
		destination[offset + 1] = (byte) getIns();
		destination[offset + 2] = (byte) getP1();
		destination[offset + 3] = (byte) getP2();
	}

	public boolean isChainedRequest() {
		return chainedRequest || nextRequest != null;
	}

	public boolean isExtendedApdu() {
		return extendedApdu || (data != null && data.length > 255)
				|| (le > 255);
	}

	public boolean isSensitiveContent() {
		return sensitiveContent;
	}

	public void setChainedRequest(boolean chainedRequest) {
		this.chainedRequest = chainedRequest;
	}

	public void setExtendedApdu(boolean extendedApdu) {
		this.extendedApdu = extendedApdu;
	}

	public void setNextRequest(RequestAPDUWrapper chainedRequest) {
		this.nextRequest = chainedRequest;
	}

	public void setSensitiveContent(boolean sensitiveContent) {
		this.sensitiveContent = sensitiveContent;
	}

	@Override
	public String toString() {
		return Hex.encodeHexString(getBytes()).replaceAll("..(?=.)", "$0 ");
		//return HexTools.bytesToHexString(getBytes());
	}

}

