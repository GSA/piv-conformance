package gov.gsa.pivconformance.card.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class APDUUtils {
    private static byte[] s_pivSelect = null;
    private static final Logger s_logger = LoggerFactory.getLogger(APDUUtils.class);

    public static byte[] PIVSelectAPDU() {
        if(s_pivSelect == null) {
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                baos.write(APDUConstants.COMMAND);
                baos.write(APDUConstants.SELECT);
                byte[] p1p2 = {0x04, 0x00};
                baos.write(p1p2);
                baos.write((byte) APDUConstants.PIV_APPID.length);
                baos.write(APDUConstants.PIV_APPID);
                s_pivSelect = baos.toByteArray();
            } catch(IOException ioe) {
                // if we ever hit this, OOM is coming soon
                s_logger.error("Unable to populate static PIV select APDU field.", ioe);
                s_pivSelect = new byte[0];
            }
        }
        return s_pivSelect;
    }

    public static byte[] PIVSelectAPDU(byte[] appid) {
        if(s_pivSelect == null) {
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                baos.write(APDUConstants.COMMAND);
                baos.write(APDUConstants.SELECT);
                byte[] p1p2 = {0x04, 0x00};
                baos.write(p1p2);
                baos.write((byte) appid.length);
                baos.write(appid);
                s_pivSelect = baos.toByteArray();
            } catch(IOException ioe) {
                // if we ever hit this, OOM is coming soon
                s_logger.error("Unable to populate static PIV select APDU field.", ioe);
                s_pivSelect = new byte[0];
            }
        }
        return s_pivSelect;
    }
}
