package gov.gsa.pivconformance.card.client;

public class APDUConstants {
    public static final byte COMMAND = 0x00;
    public static final byte COMMAND_CC = 0x10;
    public static final byte SELECT = (byte)0xa4;
    public static final byte[] PIV_APPID = { (byte)0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00 };

}
