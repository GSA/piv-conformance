
package gov.gsa.pivconformance.card.gp;

import org.apache.commons.codec.binary.Hex

import java.util.Arrays;

public final class AID {

    private byte[] aidBytes = null;

    public AID(byte[] bytes) {
        this(bytes, 0, bytes.length);
    }

    public AID(String str) {
        this(Hex.decodeHex(str));
    }

    public AID(byte[] bytes, int offset, int length) throws IllegalArgumentException {
        if ((length < 5) || (length > 16)) {
            throw new IllegalArgumentException("AIDs must be 5-16 bytes: got " + Integer.toHexString(length));
        }
        aidBytes = new byte[length];
        System.arraycopy(bytes, offset, aidBytes, 0, length);
    }

    public boolean equals(Object o) {
        if (o instanceof AID) {
            return Arrays.equals(((AID) o).aidBytes, aidBytes);
        }
        return false;
    }

    public static AID fromString(Object s) {
        if (s instanceof String) {
            return new AID(Hex.decodeHex(s));
        }
        throw new IllegalArgumentException("fromString received non-string object");
    }

    public byte[] toBytes() {
        return aidBytes.clone();
    }

    public int getLength() {
        return aidBytes.length;
    }

    public String toString() {
        return Hex.encodeHexString(aidBytes);
    }

}
