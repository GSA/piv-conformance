package gov.gsa.pivconformance.card.gp;

// interface for deriving session keys
public abstract class GPSCKeyProvider {

    // returns true if key material seems well-formed
    public abstract boolean init(byte[] atr, byte[] cplc, byte[] kinfo);

    // Parameters can be null, if inapplicable to SCP version in question
    public abstract void calculate(int scp, byte[] kdd, byte[] host_challenge, byte[] card_challenge, byte[] ssc) throws GPException;

    public abstract GPKey getKeyFor(KeyPurpose p);

    public abstract int getID();

    public abstract int getVersion();

    // Session keys are used for various purposes
    public enum KeyPurpose {
        // ID is as used in diversification/derivation
        // That is - one based.
        ENC(1), MAC(2), DEK(3), RMAC(4);

        private final int value;

        KeyPurpose(int value) {
            this.value = value;
        }

        public byte getValue() {
            return (byte) (value & 0xFF);
        }
    }

}
