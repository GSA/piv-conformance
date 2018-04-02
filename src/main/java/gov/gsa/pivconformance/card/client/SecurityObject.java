package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.*;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.icao.DataGroupHash;
import org.bouncycastle.asn1.icao.LDSSecurityObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.io.ByteArrayInputStream;

import org.bouncycastle.asn1.cms.ContentInfo;

public class SecurityObject extends PIVDataObject {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(SecurityObject.class);
    private byte[] m_mapping;
    private byte[] m_so;
    private HashMap<Integer, String> m_containerIDList;
    private CMSSignedData m_signedData;
    private ContentInfo m_contentInfo;
    HashMap<String, byte[]> m_mapOfDataElements;
    HashMap<Integer, byte[]> m_dghList;


    public SecurityObject() {
        m_mapping = null;
        m_so = null;
        m_signedData = null;
        m_containerIDList = null;
        m_contentInfo = null;
        m_mapOfDataElements = null;
        m_dghList = null;
    }

    public HashMap<String, byte[]> getMapOfDataElements() {
        return m_mapOfDataElements;
    }

    public void setMapOfDataElements(HashMap<String, byte[]> mapOfDataElements) {
        m_mapOfDataElements = mapOfDataElements;
    }

    public ContentInfo getContentInfo() {
        return m_contentInfo;
    }

    public void setContentInfo(ContentInfo contentInfo) {
        m_contentInfo = contentInfo;
    }

    public byte[] getMapping() {
        return m_mapping;
    }

    public void setMapping(byte[] mapping) {
        m_mapping = mapping;
    }

    public byte[] getSecurityObject() {
        return m_so;
    }

    public void setSecurtiyObject(byte[] so) {
        m_so = so;
    }

    public CMSSignedData getSignedData() {
        return m_signedData;
    }

    public void setSignedData(CMSSignedData signedData) {
        m_signedData = signedData;
    }


    public HashMap<Integer, String> getContainerIDList() {
        return m_containerIDList;
    }

    public void setContainerIDList(HashMap<Integer, String> containerIDList) {
        m_containerIDList = containerIDList;
    }

    public static List<byte[]> divideArray(byte[] source, int chunksize) {

        List<byte[]> result = new ArrayList<byte[]>();
        int start = 0;
        while (start < source.length) {
            int end = Math.min(source.length, start + chunksize);
            result.add(Arrays.copyOfRange(source, start, end));
            start += chunksize;
        }

        return result;
    }

    public boolean decode() {

        try {
            byte[] rawBytes = this.getBytes();
            BerTlvParser tlvp = new BerTlvParser(new CCTTlvLogger(this.getClass()));
            BerTlvs outer = tlvp.parse(rawBytes);
            List<BerTlv> outerTlvs = outer.getList();
            if (outerTlvs.size() == 1 && outerTlvs.get(0).isTag(new BerTag(0x53))) {
                byte[] tlvBuf = outerTlvs.get(0).getBytesValue();
                outer = tlvp.parse(tlvBuf);
            }
            for (BerTlv tlv : outer.getList()) {
                byte[] tag = tlv.getTag().bytes;
                if (Arrays.equals(tag, TagConstants.MAPPING_OF_DG_TO_CONTAINER_ID_TAG)) {
                    m_mapping = tlv.getBytesValue();

                    if(m_mapping == null){
                        s_logger.error("Missing mapping of DG to contains IDs for {}.", APDUConstants.oidNameMAP.get(super.getOID()));
                        return false;
                    }

                    //Break the byte array into chunks of 3
                    List<byte[]> idList = divideArray(m_mapping,3);

                    //Iterate over the resulting list to get container IDs for each
                    for(byte[] b : idList)
                    {
                        if(m_containerIDList == null)
                            m_containerIDList = new HashMap<Integer, String>();

                        byte idByte = b[0];
                        byte[] tg = Arrays.copyOfRange(b, 1, 3);
                        int i = (int) APDUUtils.bytesToInt(tg);
                        String cc = APDUConstants.idMAP.get(i);

                        int tmp = idByte;
                        Integer id = tmp;
                        //Add the container oid to the list will be easier to look up.
                        m_containerIDList.put(id, cc);
                    }


                } else if (Arrays.equals(tag, TagConstants.SECURITY_OBJECT_TAG)) {
                    m_so = tlv.getBytesValue();

                    if(m_so == null){
                        s_logger.error("Missing security object value for {}.", APDUConstants.oidNameMAP.get(super.getOID()));
                        return false;
                    }

                    //Decode the ContentInfo and get SignedData object.
                    ByteArrayInputStream bIn = new ByteArrayInputStream(m_so);
                    ASN1InputStream      aIn = new ASN1InputStream(bIn);
                    m_contentInfo = ContentInfo.getInstance(aIn.readObject());
                    m_signedData = new CMSSignedData(m_contentInfo);

                } else {
                    if (!Arrays.equals(tag, TagConstants.ERROR_DETECTION_CODE_TAG) && tlv.getBytesValue().length != 0) {
                        s_logger.warn("Unexpected tag: {} with value: {}", Hex.encodeHexString(tlv.getTag().bytes), Hex.encodeHexString(tlv.getBytesValue()));
                    }
                }
            }
        }
        catch (Exception e)
        {
            s_logger.error("Error parsing {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), e.getMessage());
        }
        return true;
    }


    public boolean verifySignature(X509Certificate signingCertificate) {
        boolean rv_result = false;

        try {
            DEROctetString newRawSo = null;
            //Create signed content if availble
            if(m_mapOfDataElements != null) {

                String defaultDigAlgName = "SHA-256";
                AlgorithmIdentifier digestAlgorithmAid = new AlgorithmIdentifier(APDUUtils.getAlgorithmIdentifier("MessageDigest", defaultDigAlgName));
                int count = 0;
                DataGroupHash ndghArray[] = new DataGroupHash[m_containerIDList.size()];

                for (HashMap.Entry<Integer, String> entry : m_containerIDList.entrySet()) {

                    byte[] containerBufferBytes = m_mapOfDataElements.get(entry.getValue());
                    MessageDigest contentDigest = MessageDigest.getInstance(defaultDigAlgName);
                    byte[] containerDigestBytes = contentDigest.digest(containerBufferBytes);
                    DataGroupHash dgHash = new DataGroupHash(entry.getKey(), (new DEROctetString(containerDigestBytes)));

                    ndghArray[count++] = dgHash;
                }

                LDSSecurityObject nldsso = new LDSSecurityObject(digestAlgorithmAid, ndghArray);

                newRawSo = new DEROctetString(nldsso.getEncoded("DER"));
            }


            CMSSignedData s = new CMSSignedData(m_contentInfo);

            //Check if signature is detached and if so used created signed content above.
            if (s.isDetachedSignature()) {
                if(newRawSo != null) {
                    CMSProcessable procesableContentBytes = new CMSProcessableByteArray(newRawSo.getOctets());
                    s = new CMSSignedData(procesableContentBytes, m_contentInfo);
                }
                else
                    s_logger.error("Error verifying signature on {}: missing signed content", APDUConstants.oidNameMAP.get(super.getOID()));
            }

            Store<X509CertificateHolder> certs = s.getCertificates();
            SignerInformationStore signers = s.getSignerInfos();

            for (Iterator<SignerInformation> i = signers.getSigners().iterator(); i.hasNext();) {
                SignerInformation signer = i.next();

                //Check if signing certificate was included
                Collection<X509CertificateHolder> certCollection = certs.getMatches(signer.getSID());
                Iterator<X509CertificateHolder> certIt = certCollection.iterator();
                if (certIt.hasNext()) {
                    X509CertificateHolder certHolder = certIt.next();
                    signingCertificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
                }

                //Check that we have a signer certificate either from the SignedData or passed in
                if(signingCertificate == null)
                    s_logger.error("Unable to find signing certificate for {}", APDUConstants.oidNameMAP.get(super.getOID()));

                try {
                    //Verify signature
                    if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(signingCertificate))) {
                        rv_result = true;
                    }
                } catch (CMSSignerDigestMismatchException e) {
                    s_logger.error("Message digest attribute value does not match calculated value for {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), e.getMessage());
                } catch (OperatorCreationException | CMSException e) {
                    s_logger.error("Error verifying signature on {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), e.getMessage());
                }
            }



        } catch (Exception ex) {
            s_logger.error("Error verifying signature on {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), ex.getMessage());
        }
        return rv_result;
    }


    public boolean verifyHashes() {
        boolean rv_result = true;

        try {

            if(m_dghList == null) {
                if (m_mapOfDataElements == null) {
                    s_logger.error("Missing list of objects to hash");
                    return false;
                }

                CMSProcessableByteArray signedContent = (CMSProcessableByteArray) m_signedData.getSignedContent();

                ASN1InputStream asn1is = new ASN1InputStream(new ByteArrayInputStream((byte[]) signedContent.getContent()));
                ASN1Sequence soSeq;
                soSeq = (ASN1Sequence) asn1is.readObject();
                asn1is.close();
                LDSSecurityObject ldsso = LDSSecurityObject.getInstance(soSeq);

                DataGroupHash [] dghList = ldsso.getDatagroupHash();
                AlgorithmIdentifier algId = ldsso.getDigestAlgorithmIdentifier();

                m_dghList = new HashMap<Integer, byte[]>();
                for (DataGroupHash entry : dghList) {
                    m_dghList.put(entry.getDataGroupNumber(), entry.getDataGroupHashValue().getOctets());
                }
            }

            for (Map.Entry<Integer, byte[]> entry : m_dghList.entrySet()) {

                String oid = m_containerIDList.get(entry.getKey());

                if(oid == null) {
                    s_logger.error("Missing object to hash for id {}: ", entry.getKey());
                    return false;
                }

                byte[] bytesToHash = m_mapOfDataElements.get(oid);

                MessageDigest md = MessageDigest.getInstance(APDUConstants.DEFAULTHASHALG);
                md.update(bytesToHash);
                byte[] digest = md.digest();

                if (!Arrays.equals(entry.getValue(), digest)) {
                    rv_result = false;
                }
            }

        } catch (Exception ex) {
            s_logger.error("Error verifying hash  on {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), ex.getMessage());
        }

        return rv_result;
    }

    public boolean verifyHash(Integer id){
        boolean rv_result = true;

        try {

            if(m_dghList == null) {
                if (m_mapOfDataElements == null) {
                    s_logger.error("Missing list of objects to hash");
                    return false;
                }

                CMSProcessableByteArray signedContent = (CMSProcessableByteArray) m_signedData.getSignedContent();

                ASN1InputStream asn1is = new ASN1InputStream(new ByteArrayInputStream((byte[]) signedContent.getContent()));
                ASN1Sequence soSeq;
                soSeq = (ASN1Sequence) asn1is.readObject();
                asn1is.close();
                LDSSecurityObject ldsso = LDSSecurityObject.getInstance(soSeq);

                DataGroupHash [] dghList = ldsso.getDatagroupHash();
                AlgorithmIdentifier algId = ldsso.getDigestAlgorithmIdentifier();

                m_dghList = new HashMap<Integer, byte[]>();
                for (DataGroupHash entry : dghList) {
                    m_dghList.put(entry.getDataGroupNumber(), entry.getDataGroupHashValue().getOctets());
                }
            }

            String oid = m_containerIDList.get(id);

            if(oid == null) {
                s_logger.error("Missing object to hash for ID {}: ", id);
                return false;
            }

            byte[] bytesToHash = m_mapOfDataElements.get(oid);

            MessageDigest md = MessageDigest.getInstance(APDUConstants.DEFAULTHASHALG);
            md.update(bytesToHash);
            byte[] digest = md.digest();

            if (!Arrays.equals(m_dghList.get(id), digest)) {
                rv_result = false;
            }

        } catch (Exception ex) {
            s_logger.error("Error verifying hash for ID: {}", id);
        }

        return rv_result;
    }

}
