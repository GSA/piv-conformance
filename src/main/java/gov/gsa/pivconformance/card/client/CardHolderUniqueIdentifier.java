package gov.gsa.pivconformance.card.client;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.pivconformance.tlv.*;
import org.apache.commons.codec.binary.Hex;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.text.SimpleDateFormat;
import java.security.MessageDigest;

public class CardHolderUniqueIdentifier extends PIVDataObject {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(CardHolderUniqueIdentifier.class);

    private byte[] m_bufferLength;
    private byte[] m_fASCN;
    private byte[] m_organizationalIdentifier;
    private byte[] m_dUNS;
    private byte[] m_gUID;
    private Date m_expirationDate;
    private byte[] m_cardholderUUID;
    private CMSSignedData m_issuerAsymmetricSignature;
    private boolean m_errorDetectionCode;
    private ContentInfo m_contentInfo;
    X509Certificate m_signingCertificate;
    private byte[] m_signedContent;
    private byte[] m_chuidContainer;


    public CardHolderUniqueIdentifier() {
        m_bufferLength = null;
        m_fASCN = null;
        m_organizationalIdentifier = null;
        m_dUNS = null;
        m_gUID = null;
        m_expirationDate = null;
        m_cardholderUUID = null;
        m_issuerAsymmetricSignature = null;
        m_errorDetectionCode = false;
        m_contentInfo = null;
        m_signingCertificate = null;
        m_signedContent = null;
        m_chuidContainer = null;
    }

    public byte[] getChuidContainer() {
        return m_chuidContainer;
    }

    public void setChuidContainer(byte[] chuidContainer) {
        m_chuidContainer = chuidContainer;
    }

    public byte[] getSignedContent() {
        return m_signedContent;
    }

    public void setSignedContent(byte[] signedContent) {
        m_signedContent = signedContent;
    }

    public X509Certificate getSigningCertificate() {
        return m_signingCertificate;
    }

    public void setSigningCertificate(X509Certificate signingCertificate) {
        m_signingCertificate = signingCertificate;
    }


    public ContentInfo getContentInfo() {
        return m_contentInfo;
    }

    public void setContentInfo(ContentInfo contentInfo) {
        m_contentInfo = contentInfo;
    }

    public byte[] getBufferLength() {
        return m_bufferLength;
    }

    public void setBufferLength(byte[] bufferLength) {
        m_bufferLength = bufferLength;
    }

    public byte[] getfASCN() {
        return m_fASCN;
    }

    public void setfASCN(byte[] fASCN) {
        m_fASCN = fASCN;
    }

    public byte[] getOrganizationalIdentifier() {
        return m_organizationalIdentifier;
    }

    public void setOrganizationalIdentifier(byte[] organizationalIdentifier) {
        m_organizationalIdentifier = organizationalIdentifier;
    }

    public byte[] getdUNS() {
        return m_dUNS;
    }

    public void setdUNS(byte[] dUNS) {
        m_dUNS = dUNS;
    }

    public byte[] getgUID() {
        return m_gUID;
    }

    public void setgUID(byte[] gUID) {
        m_gUID = gUID;
    }

    public Date getExpirationDate() {
        return m_expirationDate;
    }

    public void setExpirationDate(Date expirationDate) {
        m_expirationDate = expirationDate;
    }

    public byte[] getCardholderUUID() {
        return m_cardholderUUID;
    }

    public void setCardholderUUID(byte[] cardholderUUID) {
        m_cardholderUUID = cardholderUUID;
    }

    public CMSSignedData getIssuerAsymmetricSignature() {
        return m_issuerAsymmetricSignature;
    }

    public void setIssuerAsymmetricSignature(CMSSignedData issuerAsymmetricSignature) {
        m_issuerAsymmetricSignature = issuerAsymmetricSignature;
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

            boolean ecAdded = false;
            ByteArrayOutputStream scos = new ByteArrayOutputStream();
            ByteArrayOutputStream scos2 = new ByteArrayOutputStream();
            byte [] issuerAsymmetricSignature = null;

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
                            if (Arrays.equals(tlv2.getTag().bytes, TagConstants.BUFFER_LENGTH_TAG)) {

                                m_bufferLength = tlv2.getBytesValue();

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.FASC_N_TAG)) {


                                m_fASCN = tlv2.getBytesValue();
                                scos.write(APDUUtils.getTLV(TagConstants.FASC_N_TAG, m_fASCN));

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG)) {

                                m_organizationalIdentifier = tlv2.getBytesValue();
                                scos.write(APDUUtils.getTLV(TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG, m_organizationalIdentifier));

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.DUNS_TAG)) {

                                m_dUNS = tlv2.getBytesValue();
                                scos.write(APDUUtils.getTLV(TagConstants.DUNS_TAG, m_dUNS));

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.GUID_TAG)) {

                                m_gUID = tlv2.getBytesValue();
                                scos.write(APDUUtils.getTLV(TagConstants.GUID_TAG, m_gUID));

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.CHUID_EXPIRATION_DATE_TAG)) {

                                String s = new String(tlv2.getBytesValue());
                                Date date = new SimpleDateFormat("yyyyMMdd").parse(s);
                                m_expirationDate = date;
                                scos.write(APDUUtils.getTLV(TagConstants.CHUID_EXPIRATION_DATE_TAG, tlv2.getBytesValue()));

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.CARDHOLDER_UUID_TAG)) {

                                m_cardholderUUID = tlv2.getBytesValue();
                                if(m_cardholderUUID != null)
                                    scos.write(APDUUtils.getTLV(TagConstants.CARDHOLDER_UUID_TAG, tlv2.getBytesValue()));

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.ISSUER_ASYMMETRIC_SIGNATURE_TAG)) {

                                issuerAsymmetricSignature = tlv2.getBytesValue();

                                if(issuerAsymmetricSignature != null) {
                                    //Decode the ContentInfo and get SignedData object.
                                    ByteArrayInputStream bIn = new ByteArrayInputStream(issuerAsymmetricSignature);
                                    ASN1InputStream aIn = new ASN1InputStream(bIn);
                                    m_contentInfo = ContentInfo.getInstance(aIn.readObject());
                                    m_issuerAsymmetricSignature = new CMSSignedData(m_contentInfo);
                                }

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.ERROR_DETECTION_CODE_TAG)) {

                                if(!ecAdded) {
                                    m_errorDetectionCode = true;
                                    scos.write(TagConstants.ERROR_DETECTION_CODE_TAG);
                                    scos.write((byte) 0x00);
                                    ecAdded = true;
                                }


                            } else {
                                s_logger.warn("Unexpected tag: {} with value: {}", Hex.encodeHexString(tlv2.getTag().bytes), Hex.encodeHexString(tlv2.getBytesValue()));
                            }
                        }
                    }
                }
            }

            scos2.write(scos.toByteArray());
            //There is a bug in the encoder what adds an extar FE00 this will need to be removed for the new version
            scos.write(TagConstants.ERROR_DETECTION_CODE_TAG);
            scos.write((byte) 0x00);
            m_signedContent = scos.toByteArray();

            scos2.write(APDUUtils.getTLV(TagConstants.ISSUER_ASYMMETRIC_SIGNATURE_TAG, issuerAsymmetricSignature));
            scos2.write(TagConstants.ERROR_DETECTION_CODE_TAG);
            scos2.write((byte) 0x00);
            m_chuidContainer = scos2.toByteArray();

        }catch (Exception ex) {

            s_logger.error("Error parsing {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), ex.getMessage());
        }
        return true;
    }

    public boolean verifySignature() {
        boolean rv_result = false;

        s_logger.debug("m_signedContent HEX value: {} ", Hex.encodeHexString(m_signedContent));

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            md.update(m_signedContent);

            byte[] digest = md.digest();

            s_logger.debug("message digest value: {} ", Hex.encodeHexString(digest));
        }catch (Exception ex) {
            s_logger.error("Error calculating hash value: {}", ex.getMessage());
        }




        try {
            Security.addProvider(new BouncyCastleProvider());
        } catch (Exception e) {
            s_logger.error("Unable to add provider for signature verification: {}" , e.getMessage());
            return rv_result;
        }

        CMSSignedData s;
        try {
            s = new CMSSignedData(m_contentInfo);

            if (m_issuerAsymmetricSignature.isDetachedSignature()) {
                CMSProcessable procesableContentBytes = new CMSProcessableByteArray(m_signedContent);
                s = new CMSSignedData(procesableContentBytes, m_contentInfo);
            }

            Store<X509CertificateHolder> certs = s.getCertificates();
            SignerInformationStore signers = s.getSignerInfos();

            for (Iterator<SignerInformation> i = signers.getSigners().iterator(); i.hasNext();) {
                SignerInformation signer = i.next();

                Collection<X509CertificateHolder> certCollection = certs.getMatches(signer.getSID());
                Iterator<X509CertificateHolder> certIt = certCollection.iterator();
                if (certIt.hasNext()) {
                    X509CertificateHolder certHolder = certIt.next();
                    m_signingCertificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
                }

                if(m_signingCertificate == null)
                    s_logger.error("Unable to find signing certificate for {}", APDUConstants.oidNameMAP.get(super.getOID()));

                try {
                    if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(m_signingCertificate))) {
                        rv_result = true;
                    }
                } catch (CMSSignerDigestMismatchException e) {
                    s_logger.error("Message digest attribute value does not match calculated value for {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), e.getMessage());
                } catch (OperatorCreationException | CMSException e) {
                    s_logger.error("Error verifying signature on {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), e.getMessage());
                }
            }
        } catch (CMSException | CertificateException ex) {
            s_logger.error("Error verifying signature on {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), ex.getMessage());
        }

        return rv_result;
    }


}
