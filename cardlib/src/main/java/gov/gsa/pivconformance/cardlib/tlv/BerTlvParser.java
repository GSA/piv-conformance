package gov.gsa.pivconformance.cardlib.tlv;


import java.util.ArrayList;
import java.util.List;

/**
 *
 */
public class BerTlvParser {

    private final IBerTlvLogger log;

    public BerTlvParser() {
        this(EMPTY_LOGGER);
    }

    public BerTlvParser(IBerTlvLogger aLogger) {
        log = aLogger;
    }

    public BerTlv parseConstructed(byte[] aBuf) {
        return parseConstructed(aBuf, 0, aBuf.length);
    }

    public BerTlv parseConstructed(byte[] aBuf, int aOffset, int aLen) {
        ParseResult result =  parseWithResult(0, aBuf, aOffset, aLen, true);
        return result.tlv;
    }

    public BerTlvs parse(byte[] aBuf) {
        return parse(aBuf, 0, aBuf.length);
    }

    public BerTlvs parse(byte[] aBuf, final int aOffset, int aLen) {
        List<BerTlv> tlvs = new ArrayList<BerTlv>();
        if(aLen==0) return new BerTlvs(tlvs);

        int offset = aOffset;
        for(int i=0; i<100; i++) {
            ParseResult result =  parseWithResult(0, aBuf, offset, aLen-offset, false);
            tlvs.add(result.tlv);

            if(result.offset>=aOffset+aLen) {
                break;
            }

            offset = result.offset;

        }

        return new BerTlvs(tlvs);
    }

    private ParseResult parseWithResult(int aLevel, byte[] aBuf, int aOffset, int aLen) {
        return parseWithResult(aLevel, aBuf, aOffset, aLen, true);
    }
    private ParseResult parseWithResult(int aLevel, byte[] aBuf, int aOffset, int aLen, boolean recurse) {
        String levelPadding = createLevelPadding(aLevel);
        if(aOffset+aLen > aBuf.length) {
            throw new IllegalStateException("Length is out of the range [offset="+aOffset+",  len="+aLen+", array.length="+aBuf.length+", level="+aLevel+"]");
        }
        if(log.isDebugEnabled()) {
            log.debug("{}parseWithResult(level={}, offset={}, len={}, buf={})", levelPadding, aLevel, aOffset, aLen, HexUtil.toFormattedHexString(aBuf, aOffset, aLen));
        }

        // tag
        int tagBytesCount = getTagBytesCount(aBuf, aOffset);
        BerTag tag        = createTag(levelPadding, aBuf, aOffset, tagBytesCount);
        if(log.isDebugEnabled()) {
            log.debug("{}tag = {}, tagBytesCount={}, tagBuf={}", levelPadding, tag, tagBytesCount, HexUtil.toFormattedHexString(aBuf, aOffset, tagBytesCount));
        }

        // length
        int lengthBytesCount  = getLengthBytesCount(aBuf, aOffset + tagBytesCount);
        int valueLength       = getDataLength(aBuf, aOffset + tagBytesCount);

        if(log.isDebugEnabled()) {
            log.debug("{}lenBytesCount = {}, len = {}, lenBuf = {}"
                    , levelPadding, lengthBytesCount, valueLength, HexUtil.toFormattedHexString(aBuf, aOffset + tagBytesCount, lengthBytesCount));
        }

        // value
        if(tag.isConstructed() && recurse) {

            ArrayList<BerTlv> list = new ArrayList<BerTlv>();
            addChildren(aLevel, aBuf, aOffset, levelPadding, tagBytesCount, lengthBytesCount, valueLength, list);

            int resultOffset = aOffset + tagBytesCount + lengthBytesCount + valueLength;
            if(log.isDebugEnabled()) {
                log.debug("{}returning constructed offset = {}", levelPadding, resultOffset);
            }
            byte[] value = new byte[valueLength];
            System.arraycopy(aBuf, aOffset+tagBytesCount+lengthBytesCount, value, 0, valueLength);
            return new ParseResult(new BerTlv(tag, list, value), resultOffset);
        } else {
            // value
            byte[] value = new byte[valueLength];
            log.debug("src.length={}, srcPos={}, value.length={}, valueLength={}",
                    aBuf.length, aOffset+tagBytesCount+lengthBytesCount, value.length, valueLength);
            System.arraycopy(aBuf, aOffset+tagBytesCount+lengthBytesCount, value, 0, valueLength);
            int resultOffset = aOffset + tagBytesCount + lengthBytesCount + valueLength;
            if(log.isDebugEnabled()) {
                log.debug("{}value = {}", levelPadding, HexUtil.toFormattedHexString(value));
                log.debug("{}returning primitive offset = {}", levelPadding, resultOffset);
            }
            return new ParseResult(new BerTlv(tag, value), resultOffset);
        }

    }

    /**
     *
     * @param aLevel          level for debug
     * @param aBuf            buffer
     * @param aOffset         offset (first byte)
     * @param levelPadding    level padding (for debug)
     * @param aTagBytesCount  tag bytes count
     * @param aDataBytesCount data bytes count
     * @param valueLength     length
     * @param list            list to add
     */
    private void addChildren(int aLevel, byte[] aBuf, int aOffset, String levelPadding, int aTagBytesCount, int aDataBytesCount, int valueLength, ArrayList<BerTlv> list) {
        int startPosition = aOffset + aTagBytesCount + aDataBytesCount;
        int len = valueLength;
        while (startPosition <= aOffset + valueLength) {
            ParseResult result = parseWithResult(aLevel+1, aBuf, startPosition, len);
            list.add(result.tlv);

            startPosition = result.offset;
            len           = valueLength - startPosition;

            if(log.isDebugEnabled()) {
                log.debug("{}level {}: adding {} with offset {}, startPosition={}, aDataBytesCount={}, valueLength={}"
                        , levelPadding, aLevel, result.tlv.getTag(), result.offset, startPosition, aDataBytesCount, valueLength);
            }
        }
    }

    private String createLevelPadding(int aLevel) {
        if(!log.isDebugEnabled()) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for(int i=0; i<aLevel*4; i++) {
            sb.append(' ');
        }
        return sb.toString();
    }

    private static class ParseResult {
        public ParseResult(BerTlv aTlv, int aOffset) {
            tlv = aTlv;
            offset = aOffset;
        }

        @Override
        public String toString() {
            return "ParseResult{" +
                    "tlv=" + tlv +
                    ", offset=" + offset +
                    '}';
        }

        private final BerTlv tlv;
        private final int offset;
    }


    public BerTag createTag(String aLevelPadding, byte[] aBuf, int aOffset, int aLength) {
        if(log.isDebugEnabled()) {
            log.debug("{}Creating tag {}...", aLevelPadding, HexUtil.toFormattedHexString(aBuf, aOffset, aLength));
        }
        return new BerTag(aBuf, aOffset, aLength);
    }

    public int getTagBytesCount(byte[] aBuf, int aOffset) {
        if((aBuf[aOffset] & 0x1F) == 0x1F) { // see subsequent bytes
            int len = 2;
            for(int i=aOffset+1; i<aOffset+10; i++) {
                if( (aBuf[i] & 0x80) != 0x80) {
                    break;
                }
                len++;
            }
            return len;
        } else {
            return 1;
        }
    }


    public int getDataLength(byte[] aBuf, int aOffset) {

        int length = aBuf[aOffset] & 0xff;

        if((length & 0x80) == 0x80) {
            int numberOfBytes = length & 0x7f;
            if(numberOfBytes>3) {
                throw new IllegalStateException(String.format("At position %d the len is more then 3 [%d]", aOffset, numberOfBytes));
            }

            length = 0;
            for(int i=aOffset+1; i<aOffset+1+numberOfBytes; i++) {
                length = length * 0x100 + (aBuf[i] & 0xff);
            }

        }
        return length;
    }

    public static int getLengthBytesCount(byte[] aBuf, int aOffset) {

        int len = aBuf[aOffset] & 0xff;
        if( (len & 0x80) == 0x80) {
            return 1 + (len & 0x7f);
        } else {
            return 1;
        }
    }


    private static final IBerTlvLogger EMPTY_LOGGER = new IBerTlvLogger() {
        @Override
		public boolean isDebugEnabled() {
            return false;
        }

        @Override
		public void debug(String aFormat, Object... args) {
        }
    };


}