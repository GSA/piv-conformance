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
        byte[] rv_pivSelect = null;
        if(rv_pivSelect == null) {
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                baos.write(APDUConstants.COMMAND);
                baos.write(APDUConstants.SELECT);
                byte[] p1p2 = {0x04, 0x00};
                baos.write(p1p2);
                baos.write(appid.length);
                baos.write(appid);
                byte[] Le = {0x00};
                baos.write(Le);
                rv_pivSelect = baos.toByteArray();
            } catch(IOException ioe) {
                // if we ever hit this, OOM is coming soon
                s_logger.error("Unable to populate static PIV select APDU field.", ioe);
                rv_pivSelect = new byte[0];
            }
        }
        return rv_pivSelect;
    }

    public static byte[] PIVGetDataAPDU(byte[] data) {

        byte[] rv_pivGetData = null;

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(APDUConstants.COMMAND);
            baos.write(APDUConstants.GET);
            byte[] p1p2 = {0x3f, (byte) 0xff};
            baos.write(p1p2);
            byte[] Lc = {(byte)(data.length & 0xff)};
            baos.write(Lc);
            baos.write(data);
            byte[] Le = {0x00};
            baos.write(Le);
            rv_pivGetData = baos.toByteArray();
        } catch(IOException ioe) {
            // if we ever hit this, OOM is coming soon
            s_logger.error("Unable to populate PIV get data APDU field.", ioe);
            rv_pivGetData = new byte[0];
        }

        return rv_pivGetData;
    }

    public static final int bytesToInt(byte[] b) {

        if(b.length != 2){
            throw new IllegalArgumentException("Invalid buffer length passed in.");
        }


        int l = 0;
        l |= b[0] & 0xFF;
        l <<= 8;
        l |= b[1] & 0xFF;
        return l;
    }
}
