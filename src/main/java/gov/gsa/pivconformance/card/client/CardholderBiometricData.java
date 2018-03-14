package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.*;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;
import java.io.InputStream;
import java.io.ByteArrayInputStream;

import org.jmrtd.cbeff.*;
import org.jmrtd.lds.iso19794.*;

import java.io.IOException;

public class CardholderBiometricData extends PIVDataObject {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(CardholderBiometricData.class);


    private byte[] m_biometricData;
    private boolean m_errorDetectionCode;

    public CardholderBiometricData() {
        m_biometricData = null;
        m_errorDetectionCode = false;
    }

    public byte[] getBiometricData() {
        return m_biometricData;
    }

    public void setBiometricData(byte[] biometricData) {
        m_biometricData = biometricData;
    }

    public boolean getErrorDetectionCode() {
        return m_errorDetectionCode;
    }

    public void setErrorDetectionCode(boolean errorDetectionCode) {
        m_errorDetectionCode = errorDetectionCode;
    }


    public boolean decode() {

        try{
            byte[] rawBytes = this.getBytes();

            s_logger.warn("rawBytes: {}", Hex.encodeHexString(rawBytes));

            if(rawBytes == null){
                s_logger.error("No buffer to decode for {}.", APDUConstants.oidNameMAP.get(super.getOID()));
                return false;
            }

            BerTlvParser tlvp = new BerTlvParser(new CCTTlvLogger(this.getClass()));
            BerTlvs outer = tlvp.parse(rawBytes);

            if(outer == null){
                s_logger.error("Error parsing {}, unable to parse TLV value.", APDUConstants.oidNameMAP.get(super.getOID()));
                return false;
            }

            List<BerTlv> values = outer.getList();
            for(BerTlv tlv : values) {
                if(tlv.isPrimitive()) {
                    s_logger.info("Tag {}: {}", Hex.encodeHexString(tlv.getTag().bytes), Hex.encodeHexString(tlv.getBytesValue()));

                    BerTlvs outer2 = tlvp.parse(tlv.getBytesValue());

                    if (outer2 == null) {
                        s_logger.error("Error parsing {}, unable to parse TLV value.", APDUConstants.oidNameMAP.get(super.getOID()));
                        return false;
                    }

                    List<BerTlv> values2 = outer2.getList();
                    for (BerTlv tlv2 : values2) {
                        if (tlv2.isPrimitive()) {
                            s_logger.info("Tag {}: {}", Hex.encodeHexString(tlv2.getTag().bytes), Hex.encodeHexString(tlv2.getBytesValue()));
                        } else {
                            if (Arrays.equals(tlv2.getTag().bytes, TagConstants.FINGERPRINT_I_AND_II_TAG)) {

                                m_biometricData = tlv2.getBytesValue();

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.IMAGE_FOR_VISUAL_VERIFICATION_TAG)) {

                                m_biometricData = tlv2.getBytesValue();

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.IMAGES_FOR_IRIS_TAG)) {

                                m_biometricData = tlv2.getBytesValue();

                            }else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.ERROR_DETECTION_CODE_TAG)) {

                                m_errorDetectionCode = true;

                            } else {
                                s_logger.warn("Unexpected tag: {} with value: {}", Hex.encodeHexString(tlv2.getTag().bytes), Hex.encodeHexString(tlv2.getBytesValue()));
                            }
                        }
                    }
                }
            }
        }catch (Exception ex) {

            s_logger.error("Error parsing {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), ex.getMessage());
        }
        return true;
    }

    public boolean decodeFacialImage() {

        try
        {


            ISO781611Decoder DECODER = new ISO781611Decoder(new BiometricDataBlockDecoder<FaceInfo>() {
                public FaceInfo decode(InputStream inputStream, StandardBiometricHeader sbh, int index, int length) throws IOException {
                    return new FaceInfo(sbh, inputStream);
                }
            });

            s_logger.warn("Facial Image Data: {}", Hex.encodeHexString(m_biometricData));

            InputStream inputstream = new ByteArrayInputStream(m_biometricData);

            //Attempt to create FaceInfo object directly.
            //FaceInfo faceInfo2 = new FaceInfo(inputstream);
            //List<FaceImageInfo> faceImageInfoList = faceInfo2.getFaceImageInfos();

            ComplexCBEFFInfo complexCBEFFInfo = DECODER.decode(inputstream);
            List<CBEFFInfo> records = complexCBEFFInfo.getSubRecords();
            for (CBEFFInfo cbeffInfo: records) {
                if (!(cbeffInfo instanceof SimpleCBEFFInfo<?>)) {
                    throw new IOException("Was expecting a SimpleCBEFFInfo, found " + cbeffInfo.getClass().getSimpleName());
                }
                SimpleCBEFFInfo<?> simpleCBEFFInfo = (SimpleCBEFFInfo<?>)cbeffInfo;
                BiometricDataBlock bdb = simpleCBEFFInfo.getBiometricDataBlock();
                if (!(bdb instanceof FaceInfo)) {
                    throw new IOException("Was expecting a FaceInfo, found " + bdb.getClass().getSimpleName());
                }
                FaceInfo faceInfo = (FaceInfo)bdb;
            }

        }catch (Exception ex) {

            s_logger.error("Error parsing {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), ex.getMessage());
        }

        return true;
    }
}
