package gov.gsa.pivconformance.card.client;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import org.apache.commons.codec.binary.Hex;


// derived from the intarsys ResponseAPDU class
public class ResponseAPDUWrapper {

	private final byte[] bytes;

	public ResponseAPDUWrapper(byte[] response) throws CardClientException {
		assert (response != null);
		if (response.length < 2) {
			throw new CardClientException(
					"Invalid response received from card reader");
		}
		this.bytes = response;
	}

	public ResponseAPDUWrapper(byte[] data, int sw) {
		if (data == null) {
			data = new byte[0];
		}
		bytes = new byte[data.length + 2];
		System.arraycopy(data, 0, bytes, 0, data.length);
		bytes[data.length] = (byte) ((sw >> 8) & 0xff);
		bytes[data.length + 1] = (byte) (sw & 0xff);
	}

	public ResponseAPDUWrapper(byte[] data, int sw1, int sw2) {
		if (data == null) {
			data = new byte[0];
		}
		bytes = new byte[data.length + 2];
		System.arraycopy(data, 0, bytes, 0, data.length);
		bytes[data.length] = (byte) sw1;
		bytes[data.length + 1] = (byte) sw2;
	}

	public byte[] getBytes() {
		return bytes;
	}

	public byte[] getData() {
		byte[] data = new byte[bytes.length - 2];
		System.arraycopy(bytes, 0, data, 0, data.length);
		return data;
	}

	public int getData(byte[] pBytes, int offset, int length) {
		int count = bytes.length - 2;
		if (length < count) {
			count = length;
		}
		System.arraycopy(bytes, 0, pBytes, offset, count);
		return count;
	}

	public InputStream getInputStream() {
		return new ByteArrayInputStream(bytes, 0, bytes.length - 2);
	}

	public int getSw() {
		return ((bytes[bytes.length - 2] & 0xFF) << 8)
				+ (bytes[bytes.length - 1] & 0xFF);
	}

	public int getSw1() {
		return bytes[bytes.length - 2] & 0xFF;
	}

	public int getSw2() {
		return bytes[bytes.length - 1] & 0xFF;
	}

	public String getSwString() {
		return "0x" + Integer.toHexString(getSw1()) + ""
				+ Integer.toHexString(getSw2());
	}

	public boolean hasData() {
		return bytes.length > 2;
	}

	public boolean isOk() {
		return getSw1() == 0x90 && getSw2() == 0x00;
	}

	@Override
	public String toString() {
		return Hex.encodeHexString(getBytes()).replaceAll("..(?=.)", "$0 ");
	}

}

