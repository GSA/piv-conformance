package gov.gsa.pivconformance.card.gp;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.EnumSet;

abstract class SCPWrapper {
    protected int blockSize = 0;
    protected GPSCProvider sessionKeys = null;
    protected boolean mac = false;
    protected boolean enc = false;
    protected boolean rmac = false;
    protected boolean renc = false;


    public void setSecurityLevel(EnumSet<GlobalPlatform.SecurityLevel> securityLevel) {
        mac = securityLevel.contains(GlobalPlatform.SecurityLevel.MAC);
        enc = securityLevel.contains(GlobalPlatform.SecurityLevel.ENC);
        rmac = securityLevel.contains(GlobalPlatform.SecurityLevel.RMAC);
        renc = securityLevel.contains(GlobalPlatform.SecurityLevel.RENC);
    }

    protected int getBlockSize() {
        int res = this.blockSize;
        if (mac)
            res = res - 8;
        if (enc)
            res = res - 8;
        return res;
    }

    protected abstract CommandAPDU wrap(CommandAPDU command) throws GPSCException;

    protected abstract ResponseAPDU unwrap(ResponseAPDU response) throws GPSCException;
}
