package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.BerTag;
import gov.gsa.pivconformance.tlv.BerTlv;
import gov.gsa.pivconformance.utils.PCSCUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.ArrayList;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;


import gov.gsa.pivconformance.tlv.BerTlvParser;
import gov.gsa.pivconformance.tlv.BerTlvs;
import gov.gsa.pivconformance.tlv.HexUtil;


/**
 * Encapsulates a connection description data object (tag 0x7F21) as
 * defined by SP800-73-4 table 2
 */
public class ConnectionDescription {

    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(ConnectionDescription.class);

    private CardTerminal m_reader;

    //Tag for Connection Description template
    private static byte[] m_tag = new byte[]{(byte) 0x7F, (byte) 0x21};
    //Tag for PC/SC device reader name
    private static byte[] m_tagCRN = new byte[]{(byte) 0x81};
    //Tag for Local Network node
    private static byte[] m_tagLocal = new byte[]{(byte) 0x90, (byte) 0x00};

    /**
     * Default c'tor is private - initialize using static factory methods.
     */
    private ConnectionDescription() {
    }

    /**
     * Populate connection description data object based on information from CardTerminal
     */
    public byte[] getBytes() {

        byte[] buffer = new byte[2048];

        try {


            //Get reader name and bytes from the name
            String readerName = m_reader.getName();
            byte[] readerNameBytes = readerName.getBytes();
            int readerNameBytesLen = readerNameBytes.length;

            //Get byte value of reader name length value
            ByteBuffer bbuf = ByteBuffer.allocate(4);
            bbuf.putInt(readerNameBytesLen);
            byte[] readerNameBytesLenBuffer = bbuf.array();

            //Get offset to ignore 0x00 value
            int readerNameBytesLenBufferOffset = 0;
            while (readerNameBytesLenBuffer[readerNameBytesLenBufferOffset] == 0x00)
                readerNameBytesLenBufferOffset++;

            //Calcuate length value for the entire Connection Description Template
            int readerNameBytesPlusTagLen = readerNameBytesLen + 1 + readerNameBytesLenBuffer.length - readerNameBytesLenBufferOffset + m_tagLocal.length;

            //Get byte value of the total field length
            ByteBuffer bbuf2 = ByteBuffer.allocate(4);
            bbuf2.putInt(readerNameBytesPlusTagLen);
            byte[] readerNameBytesPlusTagLenBuffer = bbuf2.array();

            //Get offset to ignore 0x00 value
            int readerNameBytesPlusTagLenBufferOffset = 0;
            while (readerNameBytesPlusTagLenBuffer[readerNameBytesPlusTagLenBufferOffset] == 0x00)
                readerNameBytesPlusTagLenBufferOffset++;

            //Populate the final buffer
            int totalLenth = m_tag.length + (readerNameBytesPlusTagLenBuffer.length - readerNameBytesPlusTagLenBufferOffset) + m_tagCRN.length + (readerNameBytesLenBuffer.length - readerNameBytesLenBufferOffset) + readerNameBytes.length + m_tagLocal.length;

            //XXX Not sure if buffer should remain allocated for 2048 bytes.
            buffer = new byte[totalLenth];
            Arrays.fill(buffer, (byte) 0);


            ByteBuffer target = ByteBuffer.wrap(buffer);
            target.put(m_tag);
            target.put(readerNameBytesPlusTagLenBuffer, readerNameBytesPlusTagLenBufferOffset, readerNameBytesPlusTagLenBuffer.length - readerNameBytesPlusTagLenBufferOffset);
            target.put(m_tagCRN);
            target.put(readerNameBytesLenBuffer, readerNameBytesLenBufferOffset, readerNameBytesLenBuffer.length - readerNameBytesLenBufferOffset);
            target.put(readerNameBytes);
            target.put(m_tagLocal);

        }catch (Exception ex) {

            s_logger.info("Exception in getBytes of ConnectionDescription class: {}", ex.getMessage());
        }

        return buffer;
    }

    /**
     * Create a ConnectionDescription object from a javax.smartcardio.CardTerminal
     * @return ConnectionDescription used to interact with a PIV card in the specified terminal
     */
    public static ConnectionDescription createFromTerminal(CardTerminal reader) {
        ConnectionDescription rv = new ConnectionDescription();
        rv.m_reader = reader;
        return rv;
    }

    /**
     * Given the data object described in SP800-73-4 table 2, create a new connection description object
     */
    public static ConnectionDescription createFromBuffer(byte[] data) {
        ConnectionDescription rv = new ConnectionDescription();

        byte readerNameBytes[] = null;

        BerTag berTagCRN = new BerTag(m_tagCRN);
        BerTag berTag = new BerTag(m_tag);

        BerTlvParser parser = new BerTlvParser();
        BerTlvs tlvs = parser.parse(data, 0, data.length);
        BerTlv crnTlv = tlvs.find(berTag);
        BerTlv crnTlvCRN = tlvs.find(berTagCRN);

        if(crnTlv == null){
            s_logger.error("Unable to find tag for ConnectionDescription");
            return null;
        }

        if(crnTlvCRN != null)
            readerNameBytes = crnTlvCRN.getBytesValue();
        else {
            s_logger.error("Unable to find card reader name in the ConnectionDescription value");
            return null;
        }

        if(readerNameBytes == null){
            s_logger.error("Unable to find card reader name in the ConnectionDescription value");
            return null;
        }

        PCSCUtils.ConfigureUserProperties();
        try {

            TerminalFactory tf2 = TerminalFactory.getDefault();
            s_logger.info("Attempting to list card terminals");
            try {
                for (CardTerminal ct : tf2.terminals().list()) {

                    if(Arrays.equals(readerNameBytes, ct.getName().getBytes())) {

                        rv.m_reader = ct;
                    }
                }
            } catch (CardException e) {
                s_logger.error("Unable to enumerate card terminals", e);
                return null;
            }



        }catch (Exception ex) {

            s_logger.info("Exception : {}", ex.getMessage());
        }

        return rv;
    }

    /**
     * Get the reader that will be used to actually send/receive APDUs from the card
     * @return
     */
    public CardTerminal getTerminal() {
        return m_reader;
    }

}
