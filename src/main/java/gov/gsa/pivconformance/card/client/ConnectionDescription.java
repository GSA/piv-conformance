package gov.gsa.pivconformance.card.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.CardTerminal;
import java.nio.ByteBuffer;
import java.util.Arrays;


/**
 * Encapsulates a connection description data object (tag 0x7F21) as
 * defined by SP800-73-4 table 2
 */
public class ConnectionDescription {

    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(ConnectionDescription.class);

    private CardTerminal m_reader;

    /**
     * Default c'tor is private - initialize using static factory methods.
     */
    private ConnectionDescription() {
    }

    public byte[] getBytes() {

        byte[] buffer = new byte[2048];
        Arrays.fill(buffer, (byte) 0);

        try {
            //Tag for Connection Description template
            byte[] tag = new byte[]{(byte) 0x7F, (byte) 0x21};
            //Tag for PC/SC device reader name
            byte[] tagCRN = new byte[]{(byte) 0x81};
            //Tag for Local Network node
            byte[] tagLocal = new byte[]{(byte) 0x90, (byte) 0x00};

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
            int readerNameBytesPlusTagLen = readerNameBytesLen + 1 + readerNameBytesLenBuffer.length - readerNameBytesLenBufferOffset + tagLocal.length;

            //Get byte value of the total field length
            ByteBuffer bbuf2 = ByteBuffer.allocate(4);
            bbuf2.putInt(readerNameBytesPlusTagLen);
            byte[] readerNameBytesPlusTagLenBuffer = bbuf2.array();

            //Get offset to ignore 0x00 value
            int readerNameBytesPlusTagLenBufferOffset = 0;
            while (readerNameBytesPlusTagLenBuffer[readerNameBytesPlusTagLenBufferOffset] == 0x00)
                readerNameBytesPlusTagLenBufferOffset++;

            //Populate the final buffer
            ByteBuffer target = ByteBuffer.wrap(buffer);
            target.put(tag);
            target.put(readerNameBytesPlusTagLenBuffer, readerNameBytesPlusTagLenBufferOffset, readerNameBytesPlusTagLenBuffer.length - readerNameBytesPlusTagLenBufferOffset);
            target.put(tagCRN);
            target.put(readerNameBytesLenBuffer, readerNameBytesLenBufferOffset, readerNameBytesLenBuffer.length - readerNameBytesLenBufferOffset);
            target.put(readerNameBytes);
            target.put(tagLocal);

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
        return null;
    }

    /**
     * Get the reader that will be used to actually send/receive APDUs from the card
     * @return
     */
    public CardTerminal getTerminal() {
        return m_reader;
    }
}
